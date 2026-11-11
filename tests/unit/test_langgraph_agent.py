"""
Unit tests for LangGraph Agent component enrichment.
"""
import pytest
from unittest.mock import Mock, MagicMock, patch
from sqlalchemy.orm import Session
import asyncio

from app.agent.langgraph_agent.graph import ComponentEnrichmentAgent


class TestFallback2:
    """Test fallback_2 method of ComponentEnrichmentAgent."""
    
    @pytest.fixture
    def db_session(self):
        """Create a mock database session."""
        session = Mock(spec=Session)
        return session
    
    @pytest.fixture
    def agent(self, db_session):
        """Create a ComponentEnrichmentAgent instance."""
        return ComponentEnrichmentAgent(db_session)
    
    @pytest.fixture
    def mock_component(self):
        """Create a mock component."""
        component = Mock()
        component.id = 1
        component.name = "test-component"
        component.version = "1.0.0"
        component.purl = "pkg:npm/test-component@1.0.0"
        return component
    
    @pytest.mark.asyncio
    async def test_fallback_2_success(self, agent, db_session, mock_component):
        """Test fallback_2 successfully normalizes component."""
        # Setup: mock the query to return a component
        db_session.query.return_value.filter.return_value.first.return_value = mock_component
        
        # Mock the component_normalizer (imported inside the method)
        with patch('app.agent.normalizer.normalizer.component_normalizer') as mock_normalizer:
            mock_normalizer.normalize_component.return_value = ("normalized-test-component", None, None)
            
            # Create state
            state = {
                "component_id": 1,
                "name": "test-component",
                "version": "1.0.0",
                "purl": "pkg:npm/test-component@1.0.0",
                "search_name": None,
                "enrichment_method": None,
                "confidence": 0,
                "error": None
            }
            
            # Execute
            result = await agent.fallback_2(state)
            
            # Assert
            assert result["search_name"] == "normalized-test-component"
            assert result["enrichment_method"] == "fallback_2"
            assert result["confidence"] == 40
            assert result.get("error") is None
            mock_normalizer.normalize_component.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_fallback_2_component_not_found(self, agent, db_session):
        """Test fallback_2 when component is not found in database."""
        # Setup: mock the query to return None
        db_session.query.return_value.filter.return_value.first.return_value = None
        
        # Create state
        state = {
            "component_id": 999,
            "name": "nonexistent-component",
            "version": "1.0.0",
            "search_name": None,
            "enrichment_method": None,
            "confidence": 0,
            "error": None
        }
        
        # Execute
        result = await agent.fallback_2(state)
        
        # Assert
        assert result["error"] == "Fallback 2 failed"
        assert result["search_name"] is None
        assert result["enrichment_method"] is None
    
    @pytest.mark.asyncio
    async def test_fallback_2_normalizer_exception(self, agent, db_session, mock_component):
        """Test fallback_2 when component_normalizer raises an exception."""
        # Setup: mock the query to return a component
        db_session.query.return_value.filter.return_value.first.return_value = mock_component
        
        # Mock the component_normalizer (imported inside the method)
        with patch('app.agent.normalizer.normalizer.component_normalizer') as mock_normalizer:
            mock_normalizer.normalize_component.side_effect = Exception("Normalizer error")
            
            # Create state
            state = {
                "component_id": 1,
                "name": "test-component",
                "version": "1.0.0",
                "search_name": None,
                "enrichment_method": None,
                "confidence": 0,
                "error": None
            }
            
            # Execute
            result = await agent.fallback_2(state)
            
            # Assert
            assert result["error"] == "Fallback 2 failed"
            assert result["search_name"] is None
            assert result["enrichment_method"] is None
    
    @pytest.mark.asyncio
    async def test_fallback_2_preserves_other_fields(self, agent, db_session, mock_component):
        """Test that fallback_2 preserves other state fields."""
        # Setup: mock the query to return a component
        db_session.query.return_value.filter.return_value.first.return_value = mock_component
        
        # Mock the component_normalizer (imported inside the method)
        with patch('app.agent.normalizer.normalizer.component_normalizer') as mock_normalizer:
            mock_normalizer.normalize_component.return_value = ("normalized-test-component", None, None)
            
            # Create state with additional fields
            state = {
                "component_id": 1,
                "name": "test-component",
                "version": "1.0.0",
                "purl": "pkg:npm/test-component@1.0.0",
                "supplier": "test-supplier",
                "ecosystem": "npm",
                "nvd_vendor": None,
                "nvd_product": None,
                "constructed_cpe": None,
                "clean_version": "1.0.0",
                "search_name": None,
                "enrichment_method": None,
                "confidence": 0,
                "error": None
            }
            
            # Execute
            result = await agent.fallback_2(state)
            
            # Assert that other fields are preserved
            assert result["component_id"] == 1
            assert result["name"] == "test-component"
            assert result["version"] == "1.0.0"
            assert result["purl"] == "pkg:npm/test-component@1.0.0"
            assert result["supplier"] == "test-supplier"
            assert result["ecosystem"] == "npm"
            assert result["clean_version"] == "1.0.0"
