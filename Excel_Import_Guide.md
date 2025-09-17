# Excel CSV Import Guide

## Problem
When opening CSV files directly in Excel, the data may appear "weird" or improperly formatted because Excel tries to auto-detect the format and may not handle long text fields correctly.

## Solution: Proper CSV Import Method

### Method 1: Text Import Wizard (Recommended)

1. **Open Excel** (don't double-click the CSV file)

2. **Go to Data Tab** → **Get Data** → **From File** → **From Text/CSV**

3. **Select your CSV file** (e.g., `test_csv_format_demo.csv`)

4. **In the preview window:**
   - Set **File Origin** to "UTF-8" or "Windows (ANSI)"
   - Set **Delimiter** to "Comma"
   - Click **Load**

### Method 2: Import Data (Alternative)

1. **Open Excel** with a blank workbook

2. **Go to Data Tab** → **From Text/CSV**

3. **Select your CSV file**

4. **Configure import settings:**
   - Delimiter: Comma
   - Text qualifier: " (double quote)
   - File origin: UTF-8

5. **Click Load**

### Method 3: Power Query (Advanced)

1. **Data Tab** → **Get Data** → **From Other Sources** → **Blank Query**

2. **In Power Query Editor:**
   ```
   = Csv.Document(File.Contents("C:\path\to\your\file.csv"),[Delimiter=",", Columns=28, Encoding=65001])
   ```

3. **Promote first row to headers**

4. **Close & Load**

## Expected Result

After proper import, you should see:
- **Column A**: IP addresses (192.168.1.10, etc.)
- **Column B**: Hostnames (server01.local, etc.)
- **Column C**: MAC addresses
- **Column D**: Device types
- **Column E**: Scan times
- **Columns F-AB**: Individual port services with vulnerability info

## Column Formatting Tips

### Auto-fit Columns
1. **Select all columns** (Ctrl+A)
2. **Double-click** between any column headers to auto-fit all columns

### Wrap Text for Long Entries
1. **Select service columns** (F through AB)
2. **Home Tab** → **Wrap Text**
3. **Adjust row height** as needed

### Filter and Sort
1. **Select your data range**
2. **Data Tab** → **Filter**
3. **Use dropdown arrows** to filter by specific services or vulnerabilities

## Troubleshooting

### Issue: Text appears in one column
**Solution**: Use Method 1 above, ensure delimiter is set to "Comma"

### Issue: Special characters look wrong
**Solution**: Set encoding to UTF-8 during import

### Issue: Long text is cut off
**Solution**: Enable "Wrap Text" and increase row height

### Issue: Numbers treated as text
**Solution**: This is normal for IP addresses and ports - leave as text

## Quick Tips

- **Don't double-click** the CSV file to open it
- **Always use the import wizard** for best results
- **Enable text wrapping** for service columns
- **Use filters** to find specific vulnerabilities
- **Save as Excel format** (.xlsx) after importing for better performance

## Sample Data Structure

```
IP          | Hostname        | Port_22_SSH                    | Port_443_HTTPS
192.168.1.10| server01.local  | SSH (OpenSSH 7.4) | No critical| HTTPS (Apache) | No critical
192.168.1.20| database01.local| SSH (OpenSSH 8.2) | No critical| (empty)
```

This format makes it easy to:
- Sort by IP address
- Filter by specific services
- Identify critical vulnerabilities
- Export subsets of data