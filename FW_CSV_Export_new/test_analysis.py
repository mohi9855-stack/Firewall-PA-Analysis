#!/usr/bin/env python3
"""
Quick test to verify the analysis engine is working correctly.
"""
import sys
import pathlib
import tempfile

# Add the backend to the path
backend_path = pathlib.Path(__file__).parent / "backend_fastapi"
sys.path.insert(0, str(backend_path))

def test_analysis_engine():
    """Test the analysis engine with a sample Excel file."""
    print("🧪 Testing Analysis Engine...")
    
    try:
        from backend_fastapi.app.analysis import AnalysisEngine
        print("✅ Analysis engine imported successfully")
    except ImportError as e:
        print(f"❌ Failed to import analysis engine: {e}")
        return
    
    # Create a temporary directory for testing
    with tempfile.TemporaryDirectory() as temp_dir:
        temp_path = pathlib.Path(temp_dir)
        
        # Initialize the analysis engine
        engine = AnalysisEngine(temp_path)
        print(f"✅ Analysis engine initialized with data root: {temp_path}")
        
        # Check if we have any Excel files to test with
        data_root = pathlib.Path("backend_fastapi/backend_fastapi/data")
        expansions_dir = data_root / "Expansions"
        
        print(f"🔍 Looking for Excel files in: {expansions_dir}")
        
        if expansions_dir.exists():
            excel_files = list(expansions_dir.glob("*.xlsx"))
            print(f"📁 Found {len(excel_files)} Excel files")
            
            if excel_files:
                test_file = excel_files[0]
                print(f"📁 Testing with file: {test_file}")
                
                try:
                    # Test the analysis
                    result = engine.get_analysis_data_from_excel(test_file)
                    print(f"✅ Analysis completed successfully!")
                    print(f"📊 Results keys: {list(result.keys())}")
                    
                    # Check specific fields
                    for key in ['insecurePortCount', 'sourceUserNotUsed', 'totalRules', 'averageScore']:
                        if key in result:
                            print(f"📈 {key}: {result[key]}")
                        
                except Exception as e:
                    print(f"❌ Analysis failed: {e}")
                    import traceback
                    traceback.print_exc()
            else:
                print("❌ No Excel files found in Expansions directory")
        else:
            print(f"❌ Expansions directory not found: {expansions_dir}")
            print(f"🔍 Available directories in data root:")
            if data_root.exists():
                for item in data_root.iterdir():
                    print(f"  - {item.name}")
    
    print("🏁 Test completed")

if __name__ == "__main__":
    test_analysis_engine()
