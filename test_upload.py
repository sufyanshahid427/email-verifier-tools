#!/usr/bin/env python3
"""
Simple test script to verify the email verifier backend is working correctly.
Run this after starting the Flask server to test the upload functionality.
"""

import requests
import csv
import io

def create_test_csv():
    """Create a small test CSV file with sample emails."""
    test_data = [
        {"name": "John Doe", "email": "john.doe@example.com"},
        {"name": "Jane Smith", "email": "jane.smith@gmail.com"},
        {"name": "Invalid Email", "email": "invalid-email"},
        {"name": "Test User", "email": "test@nonexistentdomain12345.com"}
    ]
    
    output = io.StringIO()
    writer = csv.DictWriter(output, fieldnames=["name", "email"])
    writer.writeheader()
    writer.writerows(test_data)
    
    return output.getvalue()

def test_backend():
    """Test the backend endpoints."""
    base_url = "http://localhost:5050"
    
    print("🧪 Testing Email Verifier Backend...")
    
    # Test health endpoint
    try:
        response = requests.get(f"{base_url}/health")
        if response.status_code == 200:
            print("✅ Health check passed")
        else:
            print(f"❌ Health check failed: {response.status_code}")
            return False
    except requests.exceptions.ConnectionError:
        print("❌ Cannot connect to backend. Make sure the Flask server is running on port 5050.")
        return False
    
    # Test file upload
    try:
        csv_content = create_test_csv()
        files = {'file': ('test_emails.csv', csv_content, 'text/csv')}
        
        response = requests.post(f"{base_url}/verify", files=files)
        
        if response.status_code == 200:
            data = response.json()
            job_id = data.get('job_id')
            print(f"✅ File upload successful. Job ID: {job_id}")
            
            # Test progress endpoint
            progress_response = requests.get(f"{base_url}/progress?job_id={job_id}")
            if progress_response.status_code == 200:
                progress_data = progress_response.json()
                print(f"✅ Progress endpoint working. Progress: {progress_data.get('percent', 0)}%")
            
            return True
        else:
            print(f"❌ File upload failed: {response.status_code}")
            print(f"Response: {response.text}")
            return False
            
    except Exception as e:
        print(f"❌ Upload test failed: {str(e)}")
        return False

if __name__ == "__main__":
    success = test_backend()
    if success:
        print("\n🎉 All tests passed! Your email verifier is working correctly.")
        print("You can now upload CSV files through the web interface.")
    else:
        print("\n💥 Some tests failed. Check the error messages above.")
