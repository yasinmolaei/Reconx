# Reconx - Web Reconnaissance Tool
Reconx Made by YA$IN 

~ Uncover the shadows of the web with ReconX ~

Reconx is a Python-based command-line tool designed to automate various web reconnaissance tasks. It helps security enthusiasts, penetration testers, and bug bounty hunters gather essential information about a target domain quickly and efficiently.

## Features

*   **Whois Lookup:** Fetches and displays Whois registration information for a domain.
*   **DNS Information:** Retrieves various DNS records (A, AAAA, MX, TXT, NS, SOA, CNAME) for a domain.
*   **Web Technology Detection:** Identifies technologies used by a website (powered by Wappalyzer).
*   **Subdomain Enumeration (Intelligence):** Discovers subdomains using DNS records (MX, NS, SOA, SRV), DNS Zone Transfer attempts, and Certificate Transparency logs. Also checks for liveness of discovered subdomains.
*   **Subdomain Enumeration (Wordlist Based):** Finds subdomains using a provided wordlist. Supports "Lite" (built-in list) and "Heavy" (custom `subdomains.txt`) modes.
*   **File & Directory Enumeration:** Scans for common files and directories on a given base URL. Supports "Lite" (built-in list) and "Heavy" (custom `paths.txt`) modes.
*   **All Lookups:** Performs a comprehensive scan including Whois, DNS, Web Technologies, Intelligence Subdomain Enumeration, and an option for File & Directory Enumeration.
*   **User-Friendly Interface:** Interactive menu system with clear output, enhanced by the `rich` library for better readability.

## Requirements

*   Python 3.7+ (Recommended)
*   External libraries listed in `requirements.txt`.
*   For "full" Wappalyzer scans (Web Technology Detection), Mozilla GeckoDriver needs to be installed and in your system's PATH. You can find releases [here](https://github.com/mozilla/geckodriver/releases).

## Installation

1.  **Clone the repository:**
    ```bash
    git clone https://github.com/yasinmolaei/Reconx.git
    cd Reconx
    ```

2.  **Install dependencies:**
    It's recommended to use a virtual environment:
    ```bash
    python -m venv venv
    # On Windows
    venv\Scripts\activate
    # On macOS/Linux
    source venv/bin/activate
    ```
    Then install the required packages:
    ```bash
    pip install -r requirements.txt
    ```

## Usage

Run the script from the command line:

```bash
python reconx.py
```

This will display an interactive menu. Enter the number corresponding to the scan you want to perform and follow the prompts.

**Menu Options:**

1.  **Whois Lookup:** Enter a domain name (e.g., `example.com`).
2.  **DNS Information:** Enter a domain name.
3.  **Web Technologies Lookup:** Enter a domain name (e.g., `example.com` or `http://example.com`).
4.  **Subdomain Enumeration (Intelligence):** Enter a domain name.
5.  **Subdomain Enumeration (Wordlist Based):** Enter a domain name and choose Lite/Heavy mode.
6.  **File & Directory Enumeration:** Enter a base URL (e.g., `http://example.com`) and choose Lite/Heavy mode.
7.  **All Lookups:** Enter a domain name. This option combines Whois, DNS, Web Tech, Intelligence Subdomain Enumeration, and then prompts for a base URL for File/Directory Enumeration (Lite mode).
8.  **Exit:** Closes the tool.

### Wordlists for "Heavy" Mode

For more extensive scans, you can use the "Heavy" mode for Subdomain Enumeration and File & Directory Enumeration. This requires creating specific files in the same directory as `reconx.py`:

*   **`subdomains.txt`:** For Subdomain Enumeration (Option 5, Heavy mode).
    *   Create a file named `subdomains.txt`.
    *   Add one potential subdomain per line (e.g., `www`, `mail`, `dev`).
    *   Lines starting with `#` will be ignored as comments.

*   **`paths.txt`:** For File & Directory Enumeration (Option 6, Heavy mode).
    *   Create a file named `paths.txt`.
    *   Add one potential file or directory path per line (e.g., `admin`, `login.php`, `.env`).
    *   Lines starting with `#` will be ignored as comments.

If these files are not found or are empty when "Heavy" mode is selected, the tool will fall back to the built-in "Lite" lists.

## Contributing

Contributions, issues, and feature requests are welcome! Feel free to check the [issues page](https://github.com/yasinmolaei/Reconx.git/issues)

## License

This project can be licensed under the MIT License. See the `LICENSE` file for details.

---
