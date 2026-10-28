"""
Cleanup script to remove orphaned components (components without application_id)
This should be run after adding cascade delete to clean up existing orphaned data.
"""
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from app.core.database import SessionLocal
from app.models.component import Component

db = SessionLocal()

try:
    # Find all orphaned components (components without application_id)
    orphaned_components = db.query(Component).filter(Component.application_id == None).all()
    
    print(f"Found {len(orphaned_components)} orphaned components")
    
    if orphaned_components:
        # Delete orphaned components
        for comp in orphaned_components:
            print(f"Deleting orphaned component: {comp.name} {comp.version} (ID: {comp.id})")
            db.delete(comp)
        
        db.commit()
        print(f"Deleted {len(orphaned_components)} orphaned components")
    else:
        print("No orphaned components found")
        
except Exception as e:
    print(f"Error: {e}")
    db.rollback()
finally:
    db.close()
