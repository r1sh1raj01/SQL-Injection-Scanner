# SQL Injection Scanner

A Python-based tool designed to automate the detection of SQL injection vulnerabilities in web applications.

## Table of Contents

1. [Introduction](#introduction)
2. [Features](#features)
3. [Requirements](#requirements)
4. [Installation](#installation)
5. [Usage](#usage)
6. [Example Use Cases](#example-use-cases)
7. [Contributing](#contributing)
8. [License](#license)

## Introduction

The SQL Injection Scanner is a tool developed to identify SQL injection vulnerabilities in web applications. It uses a combination of predefined payload patterns and dynamic payload injection to detect potential weaknesses. The scanner provides a user-friendly graphical interface (GUI) for ease of use.

## Features

- **Automated Scanning:** Detects SQL injection vulnerabilities across various endpoints.
- **Multi-database support:** Compatible with MySQL and PostgreSQL.
- **Dynamic payload analysis:** Simulates real-world attacks to identify potential threats.
- **Detailed reporting:** Provides insights on detected vulnerabilities and remediation steps.
- **User-friendly interface:** Designed for both security professionals and developers to conduct quick assessments.

## Requirements

- **Python 3.x**
- **Tkinter** for GUI
- **requests** for HTTP requests
- **BeautifulSoup4** for HTML parsing (optional)

## Installation

1. Clone the repository:
git clone https://github.com/r1sh1raj01/SQL-Injection-Scanner.git


2. Create a virtual environment (optional but recommended):
python3 -m venv myenv
source myenv/bin/activate


3. Install dependencies:
pip install requests beautifulsoup4


## Usage

1. Run the scanner:
python3 scanner-gui.py


2. Enter the target URL in the GUI.
3. Click the "Scan" button to initiate the scan.
4. View the results in the GUI or save them to a file.

## Example Use Cases

- **Enterprise Security Audits:** Use the scanner to regularly test web applications for vulnerabilities.
- **Developer Security Testing:** Validate the security of your code before deployment.
- **Cybersecurity Training:** Utilize the scanner for educational purposes to demonstrate SQL injection attacks.

## Contributing

Contributions are welcome! Please submit pull requests with detailed explanations of changes.

## License

This project is released under the [MIT License](https://opensource.org/licenses/MIT).
