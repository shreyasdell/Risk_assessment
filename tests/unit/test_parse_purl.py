import pytest
from app.agent.langgraph_agent.graph import ComponentEnrichmentAgent


class TestParsePURL:
    """Unit tests for PURL parsing per PURL spec."""
    
    @pytest.fixture
    def agent(self, db_session):
        return ComponentEnrichmentAgent(db_session)
    
    @pytest.mark.asyncio
    async def test_composer_purl(self, agent):
        """Test pkg:composer/laravel/framework@5.5.0"""
        state = {
            "name": "laravel/framework",
            "version": "5.5.0",
            "purl": "pkg:composer/laravel/framework@5.5.0"
        }
        
        result = await agent.parse_purl(state)
        
        assert result.get("error") is None
        assert result["purl_type"] == "composer"
        assert result["purl_namespace"] == "laravel"
        assert result["purl_name"] == "framework"
        assert result["ecosystem"] == "composer"
        assert result["enrichment_method"] == "purl_only"
        assert result["confidence"] == 80
    
    @pytest.mark.asyncio
    async def test_npm_purl_with_encoded_namespace(self, agent):
        """Test pkg:npm/%40aws-sdk/client-ses@3.194.0"""
        state = {
            "name": "@aws-sdk/client-ses",
            "version": "3.194.0",
            "purl": "pkg:npm/%40aws-sdk/client-ses@3.194.0"
        }
        
        result = await agent.parse_purl(state)
        
        assert result.get("error") is None
        assert result["purl_type"] == "npm"
        assert result["purl_namespace"] == "@aws-sdk"  # URL-decoded from %40
        assert result["purl_name"] == "client-ses"
        assert result["ecosystem"] == "npm"
    
    @pytest.mark.asyncio
    async def test_maven_purl(self, agent):
        """Test pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1"""
        state = {
            "name": "log4j-core",
            "version": "2.14.1",
            "purl": "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1"
        }
        
        result = await agent.parse_purl(state)
        
        assert result.get("error") is None
        assert result["purl_type"] == "maven"
        assert result["purl_namespace"] == "org.apache.logging.log4j"
        assert result["purl_name"] == "log4j-core"
        assert result["ecosystem"] == "maven"
    
    @pytest.mark.asyncio
    async def test_golang_purl(self, agent):
        """Test pkg:golang/github.com/Masterminds/semver/v3@v3.2.1"""
        state = {
            "name": "semver/v3",
            "version": "v3.2.1",
            "purl": "pkg:golang/github.com/Masterminds/semver/v3@v3.2.1"
        }
        
        result = await agent.parse_purl(state)
        
        assert result.get("error") is None
        assert result["purl_type"] == "golang"
        assert result["purl_namespace"] == "github.com/Masterminds"
        assert result["purl_name"] == "semver/v3"
        assert result["ecosystem"] == "golang"
    
    @pytest.mark.asyncio
    async def test_apk_purl(self, agent):
        """Test pkg:apk/alpine/binutils@2.41-r0"""
        state = {
            "name": "binutils",
            "version": "2.41-r0",
            "purl": "pkg:apk/alpine/binutils@2.41-r0"
        }
        
        result = await agent.parse_purl(state)
        
        assert result.get("error") is None
        assert result["purl_type"] == "apk"
        assert result["purl_namespace"] == "alpine"
        assert result["purl_name"] == "binutils"
        assert result["ecosystem"] == "apk"
    
    @pytest.mark.asyncio
    async def test_deb_purl(self, agent):
        """Test pkg:deb/debian/libc6@2.31-13"""
        state = {
            "name": "libc6",
            "version": "2.31-13",
            "purl": "pkg:deb/debian/libc6@2.31-13"
        }
        
        result = await agent.parse_purl(state)
        
        assert result.get("error") is None
        assert result["purl_type"] == "deb"
        assert result["purl_namespace"] == "debian"
        assert result["purl_name"] == "libc6"
        assert result["ecosystem"] == "deb"
    
    @pytest.mark.asyncio
    async def test_purl_without_namespace(self, agent):
        """Test PURL without namespace (type/name only)"""
        state = {
            "name": "nginx",
            "version": "1.18.0",
            "purl": "pkg:generic/nginx@1.18.0"
        }
        
        result = await agent.parse_purl(state)
        
        assert result.get("error") is None
        assert result["purl_type"] == "generic"
        assert result["purl_namespace"] is None
        assert result["purl_name"] == "nginx"
        assert result["ecosystem"] == "generic"
    
    @pytest.mark.asyncio
    async def test_purl_with_qualifiers(self, agent):
        """Test PURL with qualifiers (should be stripped)"""
        state = {
            "name": "express",
            "version": "4.18.0",
            "purl": "pkg:npm/express@4.18.0?repository_url=https://github.com/expressjs/express"
        }
        
        result = await agent.parse_purl(state)
        
        assert result.get("error") is None
        assert result["purl_type"] == "npm"
        assert result["purl_namespace"] is None
        assert result["purl_name"] == "express"
        assert result["ecosystem"] == "npm"
    
    @pytest.mark.asyncio
    async def test_purl_with_subpath(self, agent):
        """Test PURL with subpath (should be stripped)"""
        state = {
            "name": "package",
            "version": "1.0.0",
            "purl": "pkg:generic/package@1.0.0#sub/path"
        }
        
        result = await agent.parse_purl(state)
        
        assert result.get("error") is None
        assert result["purl_type"] == "generic"
        assert result["purl_namespace"] is None
        assert result["purl_name"] == "package"
    
    @pytest.mark.asyncio
    async def test_purl_without_version(self, agent):
        """Test PURL without version"""
        state = {
            "name": "package",
            "version": "1.0.0",
            "purl": "pkg:generic/package"
        }
        
        result = await agent.parse_purl(state)
        
        assert result.get("error") is None
        assert result["purl_type"] == "generic"
        assert result["purl_namespace"] is None
        assert result["purl_name"] == "package"
    
    @pytest.mark.asyncio
    async def test_invalid_purl_no_pkg_prefix(self, agent):
        """Test invalid PURL without pkg: prefix"""
        state = {
            "name": "package",
            "version": "1.0.0",
            "purl": "composer/package@1.0.0"
        }
        
        result = await agent.parse_purl(state)
        
        assert result.get("error") is not None
        assert "Invalid PURL format" in result["error"]
    
    @pytest.mark.asyncio
    async def test_invalid_purl_no_slash(self, agent):
        """Test invalid PURL without slash"""
        state = {
            "name": "package",
            "version": "1.0.0",
            "purl": "pkg:package"
        }
        
        result = await agent.parse_purl(state)
        
        assert result.get("error") is not None
        assert "expected at least type/name" in result["error"]
    
    @pytest.mark.asyncio
    async def test_no_purl(self, agent):
        """Test when PURL is None"""
        state = {
            "name": "package",
            "version": "1.0.0",
            "purl": None
        }
        
        result = await agent.parse_purl(state)
        
        assert result.get("error") is not None
        assert "No PURL available" in result["error"]
