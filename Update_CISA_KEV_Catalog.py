import os
import requests

def update_cisa_kev():

    url = "https://www.cisa.gov/known-exploited-vulnerabilities-catalog"
    
    target_path = "reference_data/known_exploited_vulnerabilities.csv"
    temp_path = "reference_data/known_exploited_vulnerabilities_temp.csv"
    
    try:
        # 1. Download the latest CSV to a temporary file
        print("Downloading the latest CISA KEV catalog...")
        response = requests.get(url, timeout=30)
        
        if response.status_code != 200:
            print(f"Failed to download. CISA server responded with status code: {response.status_code}")
            return
            
        # Ensure the destination directory exists
        os.makedirs(os.path.dirname(target_path), exist_ok=True)
        
        with open(temp_path, "wb") as f:
            f.write(response.content)
            
        # 2. Perform a basic validation check on the downloaded file
        with open(temp_path, "r", encoding="utf-8") as f:
            first_line = f.readline()
            
            # Verify if the file contains the expected CSV header (CVE ID column)
            # This fails safely if an HTML page is pulled instead of raw data
            if "cveID" not in first_line:
                print("Validation failed: Invalid CSV file format or HTML error page received.")
                os.remove(temp_path)
                return
                
        # 3. Safely replace the old file with the new validated file (Overwrite)
        if os.path.exists(target_path):
            os.remove(target_path)
            
        os.rename(temp_path, target_path)
        print("CISA KEV catalog successfully updated and validated!")
        
    except Exception as e:
        print(f"An error occurred during the update process: {e}")
        # Clean up the temporary file if it still exists after a crash
        if os.path.exists(temp_path):
            os.remove(temp_path)

if __name__ == "__main__":
    update_cisa_kev()
