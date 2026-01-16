"""
Google Sheets export functionality for Cortex Analytics documentation data.

This module handles authentication and writing data to Google Sheets using a service account.
"""

import gspread
from google.oauth2.service_account import Credentials
import pandas as pd
import sys
import os


# Google Sheets Configuration
# Set these environment variables or modify them directly:
# - GOOGLE_SERVICE_ACCOUNT_FILE: Path to your service account JSON key file
# - GOOGLE_SHEET_ID: The ID of your Google Sheet (from the URL)
GOOGLE_SERVICE_ACCOUNT_FILE = os.getenv('GOOGLE_SERVICE_ACCOUNT_FILE', 'credentials.json')
GOOGLE_SHEET_ID = os.getenv('GOOGLE_SHEET_ID', '')


def authenticate_gspread():
    """Authenticate with Google Sheets using a service account

    Returns:
        gspread.Client: Authenticated gspread client
    """
    if not os.path.exists(GOOGLE_SERVICE_ACCOUNT_FILE):
        print(f"Error: Service account file not found: {GOOGLE_SERVICE_ACCOUNT_FILE}")
        print("\nTo set up service account authentication:")
        print("1. Go to Google Cloud Console")
        print("2. Navigate to IAM & Admin > Service Accounts")
        print("3. Create a service account (or use existing)")
        print("4. Create and download a JSON key file")
        print(f"5. Save it as '{GOOGLE_SERVICE_ACCOUNT_FILE}' in this directory")
        print("6. Share your Google Sheet with the service account email")
        sys.exit(1)

    scopes = [
        'https://www.googleapis.com/auth/spreadsheets',
        'https://www.googleapis.com/auth/drive'
    ]

    creds = Credentials.from_service_account_file(GOOGLE_SERVICE_ACCOUNT_FILE, scopes=scopes)

    return gspread.authorize(creds)


def write_to_google_sheets(gc, df, stats):
    """Write all data to Google Sheets with multiple tabs

    Args:
        gc: Authenticated gspread client
        df: Main DataFrame with analytics alerts
        stats: Dictionary of statistics DataFrames (keys are filenames, values are DataFrames)
    """
    if not GOOGLE_SHEET_ID:
        print("Error: GOOGLE_SHEET_ID not set. Please configure it in the script or environment variable.")
        sys.exit(1)

    try:
        # Open the spreadsheet
        spreadsheet = gc.open_by_key(GOOGLE_SHEET_ID)
        print(f"Successfully opened spreadsheet: {spreadsheet.title}")

        # Write main analytics data
        worksheet_name = "Analytics Alerts"
        try:
            worksheet = spreadsheet.worksheet(worksheet_name)
            print(f"Updating existing worksheet: {worksheet_name}")
            worksheet.clear()
        except gspread.exceptions.WorksheetNotFound:
            print(f"Creating new worksheet: {worksheet_name}")
            worksheet = spreadsheet.add_worksheet(title=worksheet_name, rows=1000, cols=20)

        # Convert DataFrame to list of lists for gspread
        data = [df.columns.tolist()] + df.fillna('').astype(str).values.tolist()
        worksheet.update(range_name='A1', values=data)
        print(f"✓ Wrote {len(df)} rows to '{worksheet_name}'")

        # Write statistics to separate tabs
        stats_mapping = {
            'count_by_sev.csv': 'Severity Counts',
            'count_by_source.csv': 'Source Counts',
            'count_by_tactic.csv': 'Tactic Counts',
            'count_by_technique.csv': 'Technique Counts',
            'count_by_tag.csv': 'Tag Counts',
            'count_by_module.csv': 'Module Counts'
        }

        for filename, sheet_name in stats_mapping.items():
            if filename in stats:
                stat_df = stats[filename].reset_index()
                stat_df.columns = [stat_df.columns[0], 'Count']

                try:
                    worksheet = spreadsheet.worksheet(sheet_name)
                    print(f"Updating existing worksheet: {sheet_name}")
                    worksheet.clear()
                except gspread.exceptions.WorksheetNotFound:
                    print(f"Creating new worksheet: {sheet_name}")
                    worksheet = spreadsheet.add_worksheet(title=sheet_name, rows=500, cols=5)

                stat_data = [stat_df.columns.tolist()] + stat_df.fillna('').astype(str).values.tolist()
                worksheet.update(range_name='A1', values=stat_data)
                print(f"✓ Wrote {len(stat_df)} rows to '{sheet_name}'")

        print(f"\n✓ All data successfully written to Google Sheets!")
        print(f"  View your spreadsheet: https://docs.google.com/spreadsheets/d/{GOOGLE_SHEET_ID}")

    except Exception as e:
        print(f"Error writing to Google Sheets: {e}")
        sys.exit(1)
