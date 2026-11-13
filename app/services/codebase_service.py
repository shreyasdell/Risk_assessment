"""
Codebase Analysis Service

Handles parsing of codebase dependencies from:
- GitHub repositories (clone and analyze)
- ZIP file uploads (extract and analyze)
- Local directory scanning

Supports multiple package managers:
- npm (package.json, package-lock.json)
- Python (requirements.txt, pyproject.toml, poetry.lock)
- Java/Maven (pom.xml)
- Gradle (build.gradle, build.gradle.kts)
- Ruby (Gemfile, Gemfile.lock)
- Go (go.mod, go.sum)
- PHP (composer.json, composer.lock)
"""

import os
import zipfile
import subprocess
import tempfile
import shutil
import logging
from typing import List, Dict, Optional
from pathlib import Path

logger = logging.getLogger(__name__)


class CodebaseAnalyzer:
    """Analyze codebase to extract dependencies"""

    def __init__(self):
        self.parsers = {
            'package.json': self._parse_npm,
            'package-lock.json': self._parse_npm_lock,
            'requirements.txt': self._parse_python,
            'pyproject.toml': self._parse_python_toml,
            'poetry.lock': self._parse_poetry_lock,
            'pom.xml': self._parse_maven,
            'build.gradle': self._parse_gradle,
            'build.gradle.kts': self._parse_gradle_kts,
            'Gemfile': self._parse_gemfile,
            'Gemfile.lock': self._parse_gemfile_lock,
            'go.mod': self._parse_go_mod,
            'go.sum': self._parse_go_sum,
            'composer.json': self._parse_composer,
            'composer.lock': self._parse_composer_lock,
        }

    def analyze_zip(self, zip_path: str) -> List[Dict]:
        """Analyze a ZIP file and extract dependencies"""
        components = []
        
        with tempfile.TemporaryDirectory() as temp_dir:
            # Extract ZIP
            with zipfile.ZipFile(zip_path, 'r') as zip_ref:
                zip_ref.extractall(temp_dir)
            
            # Analyze extracted directory
            components = self._analyze_directory(temp_dir)
        
        return components

    def analyze_github(self, github_url: str) -> List[Dict]:
        """Clone and analyze a GitHub repository"""
        components = []
        
        with tempfile.TemporaryDirectory() as temp_dir:
            try:
                # Clone repository
                subprocess.run(
                    ['git', 'clone', github_url, temp_dir],
                    check=True,
                    capture_output=True,
                    timeout=300  # 5 minute timeout
                )
                
                # Analyze cloned directory
                components = self._analyze_directory(temp_dir)
                
            except subprocess.TimeoutExpired:
                logger.error(f"Git clone timeout for {github_url}")
                raise Exception("Git clone timed out")
            except subprocess.CalledProcessError as e:
                logger.error(f"Git clone failed: {e.stderr.decode()}")
                raise Exception(f"Failed to clone repository: {e.stderr.decode()}")
        
        return components

    def _analyze_directory(self, directory: str) -> List[Dict]:
        """Recursively analyze directory for dependency files"""
        components = []
        dir_path = Path(directory)
        
        # Find all dependency files
        detected_files = []
        for file_path in dir_path.rglob('*'):
            if file_path.name in self.parsers:
                detected_files.append(file_path.name)
                try:
                    file_components = self.parsers[file_path.name](file_path)
                    # Filter out components with empty names
                    valid_components = [c for c in file_components if c.get('name') and c['name'].strip()]
                    components.extend(valid_components)
                except Exception as e:
                    logger.warning(f"Failed to parse {file_path}: {e}")
        
        logger.info(f"[codebase_analyzer] Detected files: {', '.join(detected_files)}")
        logger.info(f"[codebase_analyzer] Parsers used: {', '.join(set(detected_files))}")
        
        # Count by dependency type
        dependency_counts = {}
        for comp in components:
            dep_type = comp.get('dependency_type', 'unknown')
            dependency_counts[dep_type] = dependency_counts.get(dep_type, 0) + 1
        logger.info(f"[codebase_analyzer] Component counts by dependency_type: {dependency_counts}")
        
        return components

    def _parse_npm(self, file_path: Path) -> List[Dict]:
        """Parse package.json (no lockfile present)"""
        import json
        with open(file_path, 'r') as f:
            data = json.load(f)
        
        components = []
        
        # Parse production dependencies
        dependencies = data.get('dependencies', {})
        for name, version in dependencies.items():
            components.append({
                'name': name,
                'version': version.lstrip('^~>=<'),
                'declared_version': version,  # Store original range
                'dependency_type': 'production',
                'version_unresolved': True,  # No lockfile, version is unresolved
                'component_type': 'library',
                'purl': f'pkg:npm/{name}@{version.lstrip("^~>=<")}',
                'ecosystem': 'npm'
            })
        
        # Parse dev dependencies
        devDependencies = data.get('devDependencies', {})
        for name, version in devDependencies.items():
            components.append({
                'name': name,
                'version': version.lstrip('^~>=<'),
                'declared_version': version,  # Store original range
                'dependency_type': 'development',
                'version_unresolved': True,  # No lockfile, version is unresolved
                'component_type': 'library',
                'purl': f'pkg:npm/{name}@{version.lstrip("^~>=<")}',
                'ecosystem': 'npm'
            })
        
        return components

    def _parse_npm_lock(self, file_path: Path) -> List[Dict]:
        """Parse package-lock.json for exact versions (includes transitive dependencies)"""
        import json
        with open(file_path, 'r') as f:
            data = json.load(f)
        
        components = []
        packages = data.get('packages', {})
        
        for name, info in packages.items():
            if name.startswith('node_modules/'):
                continue  # Skip nested packages (they're duplicates)
            if not info.get('version'):
                continue
            if not name or not name.strip():
                continue  # Skip empty names
            
            # Determine dependency type
            # In package-lock.json, dev dependencies are marked with "dev": true
            dependency_type = 'development' if info.get('dev', False) else 'production'
            
            components.append({
                'name': name,
                'version': info['version'],
                'declared_version': info['version'],  # Lockfile has exact versions
                'dependency_type': dependency_type,
                'version_unresolved': False,  # Lockfile present, version is resolved
                'component_type': 'library',
                'purl': f'pkg:npm/{name}@{info["version"]}',
                'ecosystem': 'npm'
            })
        
        return components

    def _parse_python(self, file_path: Path) -> List[Dict]:
        """Parse requirements.txt"""
        components = []
        
        with open(file_path, 'r') as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                
                # Parse: package==version or package>=version
                parts = line.split('==')[0].split('>=')[0].split('<=')[0].split('~=')[0]
                name = parts.strip()
                version = line.split('==')[-1].split('>=')[-1].split('<=')[-1].split('~=')[-1].strip()
                
                if name:
                    components.append({
                        'name': name,
                        'version': version if version != name else 'latest',
                        'component_type': 'library',
                        'purl': f'pkg:pypi/{name}@{version if version != name else "latest"}',
                        'ecosystem': 'pypi'
                    })
        
        return components

    def _parse_python_toml(self, file_path: Path) -> List[Dict]:
        """Parse pyproject.toml"""
        try:
            import tomli
        except ImportError:
            logger.warning("tomli not installed, skipping pyproject.toml parsing")
            return []
        
        with open(file_path, 'rb') as f:
            data = tomli.load(f)
        
        components = []
        dependencies = data.get('project', {}).get('dependencies', [])
        
        for dep in dependencies:
            # Parse: package>=version
            if '>=' in dep:
                name, version = dep.split('>=', 1)
            else:
                name = dep
                version = 'latest'
            
            components.append({
                'name': name.strip(),
                'version': version.strip(),
                'component_type': 'library',
                'purl': f'pkg:pypi/{name.strip()}@{version.strip()}',
                'ecosystem': 'pypi'
            })
        
        return components

    def _parse_poetry_lock(self, file_path: Path) -> List[Dict]:
        """Parse poetry.lock"""
        try:
            import tomli
        except ImportError:
            logger.warning("tomli not installed, skipping poetry.lock parsing")
            return []
        
        with open(file_path, 'rb') as f:
            data = tomli.load(f)
        
        components = []
        packages = data.get('package', [])
        
        for pkg in packages:
            components.append({
                'name': pkg['name'],
                'version': pkg['version'],
                'component_type': 'library',
                'purl': f'pkg:pypi/{pkg["name"]}@{pkg["version"]}',
                'ecosystem': 'pypi'
            })
        
        return components

    def _parse_maven(self, file_path: Path) -> List[Dict]:
        """Parse pom.xml"""
        try:
            import xml.etree.ElementTree as ET
        except ImportError:
            return []
        
        tree = ET.parse(file_path)
        root = tree.getroot()
        
        components = []
        # Maven XML namespace
        ns = {'maven': 'http://maven.apache.org/POM/4.0.0'}
        
        # Parse dependencies
        for dep in root.findall('.//maven:dependency', ns):
            group_id = dep.find('maven:groupId', ns)
            artifact_id = dep.find('maven:artifactId', ns)
            version = dep.find('maven:version', ns)
            
            if group_id is not None and artifact_id is not None:
                name = f"{group_id.text}:{artifact_id.text}"
                version_text = version.text if version is not None else 'latest'
                components.append({
                    'name': name,
                    'version': version_text,
                    'component_type': 'library',
                    'purl': f'pkg:maven/{group_id.text}/{artifact_id.text}@{version_text}',
                    'ecosystem': 'maven'
                })
        
        return components

    def _parse_gradle(self, file_path: Path) -> List[Dict]:
        """Parse build.gradle"""
        components = []
        
        with open(file_path, 'r') as f:
            content = f.read()
        
        # Simple regex-based parsing (not perfect but works for common cases)
        import re
        pattern = r"implementation\s+['\"]([^:'\"]+):([^:'\"]+):([^:'\"]+)['\"]"
        
        for match in re.finditer(pattern, content):
            group, name, version = match.groups()
            full_name = f"{group}:{name}"
            components.append({
                'name': full_name,
                'version': version,
                'component_type': 'library',
                'purl': f'pkg:maven/{group}/{name}@{version}',
                'ecosystem': 'maven'
            })
        
        return components

    def _parse_gradle_kts(self, file_path: Path) -> List[Dict]:
        """Parse build.gradle.kts"""
        # Similar to build.gradle but Kotlin syntax
        return self._parse_gradle(file_path)

    def _parse_gemfile(self, file_path: Path) -> List[Dict]:
        """Parse Gemfile"""
        components = []
        
        with open(file_path, 'r') as f:
            for line in f:
                line = line.strip()
                if line.startswith('gem '):
                    # Parse: gem 'package', 'version'
                    parts = line[4:].strip().split(',')
                    name = parts[0].strip().strip("'\"")
                    version = parts[1].strip().strip("'\"") if len(parts) > 1 else 'latest'
                    components.append({
                        'name': name,
                        'version': version,
                        'component_type': 'library',
                        'purl': f'pkg:gem/{name}@{version}',
                        'ecosystem': 'rubygems'
                    })
        
        return components

    def _parse_gemfile_lock(self, file_path: Path) -> List[Dict]:
        """Parse Gemfile.lock"""
        components = []
        current_gem = None
        
        with open(file_path, 'r') as f:
            for line in f:
                line = line.strip()
                if line.startswith('  '):
                    if 'name:' in line:
                        current_gem = line.split(':')[1].strip()
                    elif 'version:' in line and current_gem:
                        version = line.split(':')[1].strip().strip("'\"")
                        components.append({
                            'name': current_gem,
                            'version': version,
                            'component_type': 'library',
                            'purl': f'pkg:gem/{current_gem}@{version}',
                            'ecosystem': 'rubygems'
                        })
                        current_gem = None
        
        return components

    def _parse_go_mod(self, file_path: Path) -> List[Dict]:
        """Parse go.mod"""
        components = []
        
        with open(file_path, 'r') as f:
            in_require = False
            for line in f:
                line = line.strip()
                if line == 'require (':
                    in_require = True
                    continue
                if line == ')':
                    in_require = False
                    continue
                if in_require and line and not line.startswith('//'):
                    parts = line.split()
                    if len(parts) >= 2:
                        name = parts[0]
                        version = parts[1].strip('"')
                        components.append({
                            'name': name,
                            'version': version,
                            'component_type': 'library',
                            'purl': f'pkg:golang/{name}@{version}',
                            'ecosystem': 'go'
                        })
        
        return components

    def _parse_go_sum(self, file_path: Path) -> List[Dict]:
        """Parse go.sum"""
        # go.sum has checksums, not useful for component extraction
        return []

    def _parse_composer(self, file_path: Path) -> List[Dict]:
        """Parse composer.json"""
        import json
        with open(file_path, 'r') as f:
            data = json.load(f)
        
        components = []
        require = data.get('require', {})
        
        for name, version in require.items():
            clean_version = version.lstrip('^~>=<')
            components.append({
                'name': name,
                'version': clean_version,
                'component_type': 'library',
                'purl': f'pkg:composer/{name}@{clean_version}',
                'ecosystem': 'php'
            })
        
        return components

    def _parse_composer_lock(self, file_path: Path) -> List[Dict]:
        """Parse composer.lock"""
        import json
        with open(file_path, 'r') as f:
            data = json.load(f)
        
        components = []
        packages = data.get('packages', [])
        
        for pkg in packages:
            name = pkg.get('name')
            if not name or not name.strip():
                continue  # Skip empty names
            components.append({
                'name': name,
                'version': pkg['version'].lstrip('v'),
                'component_type': 'library',
                'purl': f'pkg:composer/{name}@{pkg["version"].lstrip("v")}',
                'ecosystem': 'php'
            })
        
        return components


# Singleton instance
codebase_analyzer = CodebaseAnalyzer()
