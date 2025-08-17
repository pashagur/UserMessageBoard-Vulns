"""
Application version configuration.
Update this file when releasing new versions.
"""

# Application version information
VERSION = {
    'major': 1,
    'minor': 2,
    'patch': 0,
    'release': 'stable'  # Options: 'alpha', 'beta', 'rc', 'stable'
}

# Build information
BUILD_INFO = {
    'date': '2025-08-17',
    'name': 'Security Enhanced'  # Release name
}

def get_version_string():
    """Get formatted version string."""
    version_str = f"{VERSION['major']}.{VERSION['minor']}.{VERSION['patch']}"
    
    if VERSION['release'] != 'stable':
        version_str += f"-{VERSION['release']}"
    
    return version_str

def get_full_version_info():
    """Get complete version information."""
    return {
        'version': get_version_string(),
        'build_date': BUILD_INFO['date'],
        'release_name': BUILD_INFO['name'],
        'full_string': f"v{get_version_string()} ({BUILD_INFO['name']})"
    }