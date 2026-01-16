"""
Google Sheets export functionality for Cortex Analytics documentation data.

This module handles authentication and writing data to Google Sheets using a service account.
"""

import gspread
from google.oauth2.service_account import Credentials
import pandas as pd
import sys
import os
from datetime import datetime


# Google Sheets Configuration
# Set these environment variables or modify them directly:
# - GOOGLE_SERVICE_ACCOUNT_FILE: Path to your service account JSON key file
# - GOOGLE_SHEET_ID: The ID of your Google Sheet (from the URL)
GOOGLE_SERVICE_ACCOUNT_FILE = os.getenv('GOOGLE_SERVICE_ACCOUNT_FILE', 'credentials.json')
GOOGLE_SHEET_ID = os.getenv('GOOGLE_SHEET_ID', '')

# Sheet layout configuration
# Specify the tab names and cell ranges for each data element
SHEET_CONFIG = {
    'summary_stats_tab': 'Summary Statistics',
    'all_detectors_tab': 'All Detectors',

    # Cell ranges for summary statistics (adjust these to match your sheet layout)
    # Format: 'A1' for top-left corner where data starts (headers + data will be written)
    # All tables in one row, each taking 3 columns
    'stats_ranges': {
        'count_by_sev.csv': 'A1',        # Severity counts starting at A1
        'count_by_source.csv': 'D1',     # Source counts starting at D1
        'count_by_tactic.csv': 'G1',     # Tactic counts starting at G1
        'count_by_technique.csv': 'J1',  # Technique counts starting at J1
        'count_by_tag.csv': 'M1',        # Tag counts starting at M1
        'count_by_module.csv': 'P1',     # Module counts starting at P1
    },

    # Cell range for all detectors data
    # Format: 'A3' means headers start at row 3, data starts at row 4
    # This preserves rows 1-2
    'detectors_range': 'A3',
}


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
    """Write data to specific ranges in Google Sheets, preserving existing formatting

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

        # Write summary statistics to their designated ranges
        summary_tab = SHEET_CONFIG['summary_stats_tab']
        try:
            worksheet = spreadsheet.worksheet(summary_tab)
            print(f"Updating '{summary_tab}' tab...")

            # Clear all existing content AND formatting in the tab before writing new data
            # Use the API to clear both values and formats
            clear_request = {
                "requests": [{
                    "updateCells": {
                        "range": {
                            "sheetId": worksheet.id
                        },
                        "fields": "userEnteredValue,userEnteredFormat"
                    }
                }]
            }
            spreadsheet.batch_update(clear_request)
            print(f"  ✓ Cleared existing content and formatting")

            # Calculate dynamic positions for tables with 2 empty rows between stacked tables
            # Layout:
            # Row 1: Sources (A1), Tactic (D1), Technique (G1)
            # Below Sources (+3 for 2 empty rows): Detector Tags
            # Below Tactic (+3): Severity, then below that (+3): Detection Modules

            # Get table sizes (rows of data + 1 for header)
            source_rows = len(stats.get('count_by_source.csv', [])) + 1
            tactic_rows = len(stats.get('count_by_tactic.csv', [])) + 1
            sev_rows = len(stats.get('count_by_sev.csv', [])) + 1

            # Calculate starting rows with 3-row spacing (table end + 2 empty rows + 1 for next table start)
            tag_start_row = source_rows + 3
            sev_start_row = tactic_rows + 3
            module_start_row = sev_start_row + sev_rows + 3

            # Map filenames to their dynamic cell ranges
            dynamic_ranges = {
                'count_by_source.csv': 'A1',
                'count_by_tactic.csv': 'D1',
                'count_by_technique.csv': 'G1',
                'count_by_tag.csv': f'A{tag_start_row}',
                'count_by_sev.csv': f'D{sev_start_row}',
                'count_by_module.csv': f'D{module_start_row}',
            }

            # Prepare formatting requests
            format_requests = []

            for filename, cell_range in dynamic_ranges.items():
                if filename in stats:
                    stat_df = stats[filename].reset_index()
                    stat_df.columns = [stat_df.columns[0], 'Count']

                    # Convert DataFrame to list of lists (headers + data)
                    stat_data = [stat_df.columns.tolist()] + stat_df.fillna('').astype(str).values.tolist()

                    # Update the specific range
                    worksheet.update(range_name=cell_range, values=stat_data)
                    print(f"  ✓ Wrote {len(stat_df)} rows for {filename.replace('.csv', '')} at {cell_range}")

                    # Calculate the range for this table
                    # Extract column letter and row number from cell_range (e.g., 'A' and '1' from 'A1')
                    import re
                    match = re.match(r'([A-Z]+)(\d+)', cell_range)
                    start_col_letter = match.group(1)
                    start_row = int(match.group(2))

                    # Convert column letter to 0-based index
                    start_col_idx = ord(start_col_letter) - ord('A')
                    end_col_idx = start_col_idx + 2  # 2 columns per table (label + count)
                    num_rows = len(stat_df) + 1  # +1 for header

                    # Convert to 0-based row index
                    start_row_idx = start_row - 1

                    # Set font size 8 for all cells in this table
                    format_requests.append({
                        "repeatCell": {
                            "range": {
                                "sheetId": worksheet.id,
                                "startRowIndex": start_row_idx,
                                "endRowIndex": start_row_idx + num_rows,
                                "startColumnIndex": start_col_idx,
                                "endColumnIndex": end_col_idx
                            },
                            "cell": {
                                "userEnteredFormat": {
                                    "textFormat": {
                                        "fontSize": 8
                                    }
                                }
                            },
                            "fields": "userEnteredFormat.textFormat.fontSize"
                        }
                    })

                    # Add bold formatting and light gray background for first column (all rows)
                    # Apply this BEFORE header row so header row can override for cell A1
                    format_requests.append({
                        "repeatCell": {
                            "range": {
                                "sheetId": worksheet.id,
                                "startRowIndex": start_row_idx,
                                "endRowIndex": start_row_idx + num_rows,
                                "startColumnIndex": start_col_idx,
                                "endColumnIndex": start_col_idx + 1  # Just the first column
                            },
                            "cell": {
                                "userEnteredFormat": {
                                    "textFormat": {
                                        "bold": True
                                    },
                                    "backgroundColor": {
                                        "red": 0.85,
                                        "green": 0.85,
                                        "blue": 0.85
                                    }
                                }
                            },
                            "fields": "userEnteredFormat(textFormat.bold,backgroundColor)"
                        }
                    })

                    # Add bold formatting and medium-dark gray background for header row
                    # Apply this AFTER first column so it overrides the background color for cell A1
                    format_requests.append({
                        "repeatCell": {
                            "range": {
                                "sheetId": worksheet.id,
                                "startRowIndex": start_row_idx,
                                "endRowIndex": start_row_idx + 1,
                                "startColumnIndex": start_col_idx,
                                "endColumnIndex": end_col_idx
                            },
                            "cell": {
                                "userEnteredFormat": {
                                    "textFormat": {
                                        "bold": True
                                    },
                                    "backgroundColor": {
                                        "red": 0.6,
                                        "green": 0.6,
                                        "blue": 0.6
                                    }
                                }
                            },
                            "fields": "userEnteredFormat(textFormat.bold,backgroundColor)"
                        }
                    })

                    # Add borders around the entire table
                    border_style = {
                        "style": "SOLID",
                        "width": 1,
                        "color": {"red": 0, "green": 0, "blue": 0}
                    }
                    format_requests.append({
                        "updateBorders": {
                            "range": {
                                "sheetId": worksheet.id,
                                "startRowIndex": start_row_idx,
                                "endRowIndex": start_row_idx + num_rows,
                                "startColumnIndex": start_col_idx,
                                "endColumnIndex": end_col_idx
                            },
                            "top": border_style,
                            "bottom": border_style,
                            "left": border_style,
                            "right": border_style,
                            "innerHorizontal": border_style,
                            "innerVertical": border_style
                        }
                    })

            # Apply all formatting in a single batch request
            if format_requests:
                spreadsheet.batch_update({"requests": format_requests})
                print(f"  ✓ Applied formatting (bold headers and borders)")

        except gspread.exceptions.WorksheetNotFound:
            print(f"Error: Worksheet '{summary_tab}' not found. Please create it first.")
            sys.exit(1)

        # Write all detectors data to its designated range
        detectors_tab = SHEET_CONFIG['all_detectors_tab']
        try:
            worksheet = spreadsheet.worksheet(detectors_tab)
            print(f"\nUpdating '{detectors_tab}' tab...")

            # Update cell A1 with "LAST UPDATED: MM/DD/YYYY" (preserves existing formatting)
            current_date = datetime.now().strftime("%m/%d/%Y")
            last_updated_text = f"LAST UPDATED: {current_date}"
            worksheet.update(range_name='A1', values=[[last_updated_text]], value_input_option='RAW')
            print(f"  ✓ Set last updated date: {current_date}")

            # Convert DataFrame to list of lists (data only, no headers)
            # Headers are already in row 2, so we only write the data
            data = df.fillna('').astype(str).values.tolist()

            # Update the specific range
            detectors_range = SHEET_CONFIG['detectors_range']
            worksheet.update(range_name=detectors_range, values=data)
            print(f"  ✓ Wrote {len(df)} detector rows starting at {detectors_range}")

            # Copy formulas from row 3 (columns N:AS) down to all data rows
            # This uses the Sheets API to copy formulas so they auto-adjust row references
            num_data_rows = len(df)
            if num_data_rows > 1:
                # Build a batch update request to copy formulas from N3:AS3 to rows 4 onwards
                # Column N is index 13 (0-based), Column AS is index 44 (0-based)
                requests = [{
                    "copyPaste": {
                        "source": {
                            "sheetId": worksheet.id,
                            "startRowIndex": 2,  # Row 3 (0-based index)
                            "endRowIndex": 3,    # Exclusive, so just row 3
                            "startColumnIndex": 13,  # Column N
                            "endColumnIndex": 45     # Column AS + 1 (exclusive)
                        },
                        "destination": {
                            "sheetId": worksheet.id,
                            "startRowIndex": 3,  # Row 4 (0-based index)
                            "endRowIndex": 2 + num_data_rows,  # Through last data row
                            "startColumnIndex": 13,  # Column N
                            "endColumnIndex": 45     # Column AS + 1 (exclusive)
                        },
                        "pasteType": "PASTE_FORMULA"
                    }
                }]

                spreadsheet.batch_update({"requests": requests})
                print(f"  ✓ Copied formulas from N3:AS3 to N4:AS{2 + num_data_rows}")

        except gspread.exceptions.WorksheetNotFound:
            print(f"Error: Worksheet '{detectors_tab}' not found. Please create it first.")
            sys.exit(1)

        print(f"\n✓ All data successfully written to Google Sheets!")
        print(f"  View your spreadsheet: https://docs.google.com/spreadsheets/d/{GOOGLE_SHEET_ID}")

    except Exception as e:
        print(f"Error writing to Google Sheets: {e}")
        sys.exit(1)
