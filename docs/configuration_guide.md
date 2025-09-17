# Default Flags Configuration Guide

## Overview

The network mapper now supports configurable default values for all command-line flags through a JSON configuration file. This allows you to customize the tool's behavior without modifying the source code.

## Configuration File Location

The configuration file is located at: `config/default_flags.json`

## Configuration Structure

The configuration file is organized into several sections:

### Scan Options
Controls basic scanning parameters:
- `threads`: Number of concurrent threads (default: 50)
- `timeout`: Connection timeout in seconds (default: 3)
- `format`: Output format - "json" or "csv" (default: "json")

### Feature Flags
Controls which features are enabled by default:
- `ping_only`: Only perform ping sweep (default: false)
- `nmap`: Use nmap for advanced scanning (default: false)
- `smart_filter`: Filter common infrastructure IPs (default: true)
- `vuln_report`: Generate vulnerability reports (default: false)
- `incremental`: Enable incremental export mode (default: false)

### Security Options
Controls security-related features:
- `rate_limiting`: Enable rate limiting (default: true)
- `input_validation`: Enable input validation (default: true)
- `secure_logging`: Enable secure logging (default: true)

### Output Options
Controls output behavior:
- `auto_export`: Automatically generate output files (default: false)
- `default_output_prefix`: Prefix for auto-generated files (default: "scan")

## Usage Examples

### Viewing Current Configuration
```bash
python network_mapper_refactored.py --show-config
```

### Resetting to Factory Defaults
```bash
python network_mapper_refactored.py --reset-config
```

### Customizing Defaults

Edit `config/default_flags.json` to change default values:

```json
{
  "scan_options": {
    "threads": {"value": 100, "description": "Increase for faster scanning"},
    "timeout": {"value": 5, "description": "Longer timeout for slow networks"},
    "format": {"value": "csv", "description": "Default to CSV output"}
  },
  "feature_flags": {
    "nmap": {"enabled": true, "description": "Always use nmap by default"},
    "vuln_report": {"enabled": true, "description": "Always generate vulnerability reports"}
  }
}
```

### Running with Custom Defaults

Once configured, simply run the tool normally:
```bash
# This will now use your custom defaults
python network_mapper_refactored.py 192.168.1.0/24

# Override specific settings as needed
python network_mapper_refactored.py 192.168.1.0/24 --threads 200 --no-nmap
```

## Common Configuration Scenarios

### High-Speed Scanning Profile
```json
{
  "scan_options": {
    "threads": {"value": 200},
    "timeout": {"value": 1}
  },
  "feature_flags": {
    "nmap": {"enabled": true},
    "smart_filter": {"enabled": false}
  }
}
```

### Security Assessment Profile
```json
{
  "feature_flags": {
    "nmap": {"enabled": true},
    "vuln_report": {"enabled": true},
    "incremental": {"enabled": true}
  },
  "output_options": {
    "auto_export": {"enabled": true}
  }
}
```

### Conservative Scanning Profile
```json
{
  "scan_options": {
    "threads": {"value": 10},
    "timeout": {"value": 10}
  },
  "security_options": {
    "rate_limiting": {"enabled": true}
  }
}
```

## Tips and Best Practices

1. **Backup Configuration**: The `--reset-config` command automatically creates a backup
2. **Test Changes**: Use `--show-config` to verify your configuration before scanning
3. **Environment-Specific Configs**: Consider different configurations for different environments
4. **Version Control**: Include your configuration file in version control for team consistency
5. **Documentation**: Update the description fields when modifying values

## Troubleshooting

### Configuration Not Loading
- Ensure the file exists at `config/default_flags.json`
- Check JSON syntax with a validator
- Verify file permissions

### Invalid Values
- Check that numeric values are within valid ranges
- Ensure boolean values are `true` or `false`
- Verify string values match expected options

### Reverting Changes
Use `--reset-config` to restore factory defaults, or manually restore from the `.backup` file created during reset.