🛡️ CodeAlpha Secure Code Review

A Python-based secure coding project demonstrating vulnerability identification, remediation, automated testing, and static security analysis.

![Python](https://img.shields.io/badge/Python-3.10%2B-3776AB?logo=python&logoColor=white) ![FastAPI](https://img.shields.io/badge/FastAPI-API-009688?logo=fastapi&logoColor=white) ![SQLite](https://img.shields.io/badge/Database-SQLite-003B57?logo=sqlite&logoColor=white) ![Security](https://img.shields.io/badge/Focus-Application%20Security-red) ![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)

Author: Bejjam Charan Sai Teja
Project: CodeAlpha Cybersecurity Internship — Secure Code Review
Repository: CodeAlpha_SecureCodeReview

📌 Overview

CodeAlpha Secure Code Review is an educational cybersecurity project focused on identifying insecure coding practices, implementing safer alternatives, and validating security improvements through automated tests and static analysis.

The project separates intentionally vulnerable code examples from a corrected FastAPI application. It demonstrates how security weaknesses can be investigated, remediated, and tested in a controlled local environment.

The application uses SQLite for data storage and requires API-key authentication for protected endpoints. It incorporates input validation, parameterized SQL queries, constant-time API-key comparison, and defensive HTTP security headers.

Security testing is supported by Bandit, Semgrep, and pytest.

🎯 Objectives
Understand common application security weaknesses.
Compare vulnerable code with corrected implementations.
Demonstrate protection against SQL injection.
Implement API-key authentication and input validation.
Apply defensive HTTP security headers.
Verify expected application behavior with automated tests.
Use static analysis to identify potential security issues.
Document security findings, remediation steps, and residual risks.
✨ Key Features
Feature	Description
🔐 API-key authentication	Protects application endpoints using the X-API-Key header.
🧪 Input validation	Validates item names and request parameters.
🛡️ SQL injection prevention	Uses parameterized SQLite queries instead of string-built SQL statements.
🔎 Search functionality	Searches stored items using a parameterized query.
🧱 Security headers	Adds defensive HTTP response headers.
🧰 Static analysis	Supports Bandit and Semgrep security scans.
✅ Automated testing	Tests authentication, validation, database operations, and error handling.
📚 Vulnerability education	Keeps intentionally insecure examples separate from corrected application code.
📝 Security documentation	Organizes review findings and remediation information in the reports directory.
🏗️ Project Architecture

The project consists of an application, vulnerable examples, tests, static-analysis rules, and security reports.

text
CodeAlpha_SecureCodeReview/
│
├── app/
│   └── main.py                 # Corrected FastAPI application
│
├── vulnerable_samples/        # Intentionally insecure examples
│
├── tests/
│   └── test_app.py             # Automated regression tests
│
├── .semgrep/
│   └── rules.yml               # Custom Semgrep rules
│
├── reports/                   # Security findings and remediation
│
├── scripts/                   # Supporting scripts
│
├── requirements.txt            # Application and testing dependencies
├── .gitignore                  # Excluded files and environments
├── README.md                   # Project documentation
└── LICENSE                     # MIT License


Directory contents may evolve as the project develops.

🔄 Security Review Workflow

The workflow moves from identifying weaknesses to validating their remediation.

text
1. Review Source Code
         ↓
2. Identify Potential Vulnerabilities
         ↓
3. Reproduce and Understand the Risk
         ↓
4. Implement Secure Coding Practices
         ↓
5. Run Automated Regression Tests
         ↓
6. Execute Bandit and Semgrep
         ↓
7. Review Findings and False Positives
         ↓
8. Document Remediation and Residual Risks

Step 1 — Review the source code

Inspect the application and the intentionally vulnerable examples to understand the security problems being demonstrated.

Step 2 — Identify weaknesses

Look for unsafe database queries, missing authentication, insufficient validation, and other insecure implementation patterns.

Step 3 — Remediate the weaknesses

Apply appropriate controls, including parameterized SQL queries, API-key authentication, input constraints, and secure response headers.

Step 4 — Run regression tests

Use pytest to check that security controls work as expected and that normal application functionality remains intact.

Step 5 — Run static analysis

Use Bandit and Semgrep to identify suspicious coding patterns. Investigate each finding rather than automatically treating every alert as a confirmed vulnerability.

Step 6 — Document the results

Record the issue, potential impact, remediation, test evidence, and any remaining limitations.

💻 Installation
Prerequisites

Install the following software before starting:

Python 3.10 or newer, with a compatible version supported by the dependencies.
Git.
A terminal: PowerShell or Command Prompt on Windows, or a shell on Linux.
Internet access to download the dependencies.

Python virtual environments are recommended to isolate project dependencies.

🪟 Windows Installation

These commands use PowerShell.

1. Clone the repository

powershell
git clone https://github.com/charansaiteja-cloud/CodeAlpha_SecureCodeReview.git
cd CodeAlpha_SecureCodeReview


2. Create a virtual environment

powershell
py -m venv .venv


3. Activate the environment

powershell
.\.venv\Scripts\Activate.ps1


If PowerShell blocks activation because of the execution policy, you can use Command Prompt instead:

bat
.venv\Scripts\activate.bat


Alternatively, invoke the environment's Python executable directly without activating it.

4. Upgrade pip and install dependencies

powershell
python -m pip install --upgrade pip
python -m pip install -r requirements.txt


5. Configure the local API key and database

powershell
$env:LAB_API_KEY = "local-demo-key-change-me"
$env:LAB_DB_PATH = "$env:TEMP\codealpha_review.sqlite3"


Use a unique secret instead of the example key for any environment beyond local demonstration.

6. Start the application

powershell
python -m uvicorn app.main:app --host 127.0.0.1 --port 8000


Open the following address in your browser:

Application API: http://127.0.0.1:8000
Interactive API documentation: http://127.0.0.1:8000/docs
Health check: http://127.0.0.1:8000/health

Keep the server running while testing the API.

🐧 Linux Installation

These commands use Bash on Linux distributions such as Ubuntu, Debian, and Kali Linux.

1. Clone the repository

bash
git clone https://github.com/charansaiteja-cloud/CodeAlpha_SecureCodeReview.git
cd CodeAlpha_SecureCodeReview


2. Install Python and virtual-environment support if necessary

For Debian-based distributions:

bash
sudo apt update
sudo apt install python3 python3-venv python3-pip git


3. Create and activate the environment

bash
python3 -m venv .venv
source .venv/bin/activate


4. Install project dependencies

bash
python -m pip install --upgrade pip
python -m pip install -r requirements.txt


5. Configure the application

bash
export LAB_API_KEY='local-demo-key-change-me'
export LAB_DB_PATH='/tmp/codealpha_review.sqlite3'


Use an appropriately protected database path and a unique secret for your own environment.

6. Start the application

bash
python -m uvicorn app.main:app --host 127.0.0.1 --port 8000


Open http://127.0.0.1:8000/docs to explore and test the API.

Security note: The example API key is for local testing only. Do not use it in production or commit real credentials to Git.
🚀 How to Use the Application

Once the server is running, you can interact with the API through Swagger UI at /docs, an HTTP client, or curl.

1. Check application health

The health endpoint does not require an API key.

bash
curl http://127.0.0.1:8000/health


Expected response:

json
{
  "status": "ok"
}

2. Read an item

Protected endpoints require the X-API-Key header.

bash
curl -H "X-API-Key: local-demo-key-change-me" \
  http://127.0.0.1:8000/items/1


The database initializes a demonstration item with ID 1.

3. Create an item
bash
curl -X POST http://127.0.0.1:8000/items \
  -H "Content-Type: application/json" \
  -H "X-API-Key: local-demo-key-change-me" \
  -d '{"name":"Secure Coding Demo"}'


A successful request returns HTTP 201 with the created item's ID and name.

Valid names must contain between 1 and 80 characters and use the permitted letters, numbers, underscores, spaces, periods, or hyphens.

4. Search for items
bash
curl -G http://127.0.0.1:8000/search \
  -H "X-API-Key: local-demo-key-change-me" \
  --data-urlencode "q=Secure"


The search endpoint accepts a query between 1 and 80 characters and returns matching items, limited to 20 results.

API Endpoint Reference
Method	Endpoint	Authentication	Purpose
GET	/health	Not required	Check application health.
GET	/items/{item_id}	Required	Retrieve an item by ID.
POST	/items	Required	Create a validated item.
GET	/search?q=...	Required	Search items by name.
GET	/docs	Not required by default	Explore the interactive API documentation.
Authentication and Error Handling
Missing or incorrect API keys produce HTTP 401 Unauthorized on protected endpoints.
Invalid item IDs or request parameters produce validation errors.
Requests for nonexistent items return HTTP 404 Not Found.
The application fails closed when its API key is not configured: protected endpoints remain inaccessible.
🔍 Security Testing and Static Analysis

Run these checks from the repository root.

1. Run the automated tests
bash
python -m pytest -v


The tests cover health and security headers, API-key authentication, configuration failures, item retrieval, input validation, creation, searching, and SQL metacharacter handling.

2. Run Bandit
bash
bandit -r app -ll


Bandit performs static analysis on Python code and reports potential security issues according to its enabled rules and severity threshold.

To include the educational vulnerable examples in the scan:

bash
bandit -r app vulnerable_samples -f txt


Findings in intentionally insecure samples should be reviewed separately from findings in the corrected application.

3. Run custom Semgrep rules

For isolation from the main application's dependencies, use a dedicated virtual environment.

Linux:

bash
python3 -m venv .semgrep-venv
.semgrep-venv/bin/python -m pip install semgrep

.semgrep-venv/bin/semgrep scan \
  --config .semgrep/rules.yml app vulnerable_samples


Windows PowerShell:

powershell
py -m venv .semgrep-venv
.\.semgrep-venv\Scripts\python.exe -m pip install semgrep

.\.semgrep-venv\Scripts\semgrep.exe scan `
  --config .semgrep/rules.yml app vulnerable_samples

4. Run the broader Semgrep OSS ruleset

Linux:

bash
.semgrep-venv/bin/semgrep scan --config auto app vulnerable_samples


Windows PowerShell:

powershell
.\.semgrep-venv\Scripts\semgrep.exe scan --config auto app vulnerable_samples


The auto configuration uses Semgrep's available registry rules. Network access may be required to retrieve rules. Additional Semgrep products and rules may require account access.

5. Check dependency consistency

Run this command inside the main .venv:

bash
python -m pip check


It verifies that the installed packages satisfy their declared dependency requirements.

Important: Keep Semgrep in .semgrep-venv rather than installing it into the main application environment if its OpenTelemetry dependencies conflict with FastAPI.

📊 Verified Project Results

During the documented local verification run, the project produced these results:

Verification	Result
Automated tests	13 passed
Bandit scan	No issues identified
Custom Semgrep rules	0 findings
Semgrep OSS scan	0 findings across 2 tracked files
Dependency consistency	No broken requirements
Git repository	Clean working tree after commit

These results describe a specific verification run, not a guarantee that future versions or every file are vulnerability-free.

🛡️ Security Practices Demonstrated
Parameterized SQL queries

Database operations use parameter binding rather than interpolating user-controlled input into SQL statements.

python
db.execute(
    "SELECT id, name FROM items WHERE id = ?",
    (item_id,)
)


This separates SQL syntax from supplied values and helps prevent SQL injection.

API-key verification

The application compares the configured API key with the supplied X-API-Key using hmac.compare_digest. Protected endpoints reject missing, incorrect, or unconfigured credentials.

Input validation

Pydantic validates item names and request parameters against defined length and character constraints.

Defensive HTTP headers

The application adds headers including:

X-Content-Type-Options: nosniff
X-Frame-Options: DENY
Cache-Control: no-store
Referrer-Policy: no-referrer
Content-Security-Policy: default-src 'none'

These controls help mitigate selected classes of browser-side and response-handling risks. They do not replace a complete production security configuration.

⚠️ Troubleshooting
python or python3 is not found

Install Python and ensure it is available on your system's PATH. On Windows, the Python launcher py may also be available.

Virtual-environment activation fails

Use the correct activation command for your shell, or invoke .venv's Python executable directly.

semgrep: command not found

Semgrep is installed in the separate environment. Run it through .semgrep-venv/bin/semgrep on Linux or .semgrep-venv\Scripts\semgrep.exe on Windows.

pip check reports dependency conflicts

Activate the main .venv, reinstall the project's declared dependencies, and check again. Avoid installing Semgrep into that same environment when it causes incompatible dependency requirements.

Protected endpoints return HTTP 401

Confirm that LAB_API_KEY is configured in the same terminal session that starts the server. Send the exact matching key in the X-API-Key header.

The database cannot be opened

Ensure the configured database path is valid and its parent directory exists and is writable by the current user.

🔮 Future Improvements

Potential extensions include:

Automated CI security checks using GitHub Actions.
Structured security reports in JSON or SARIF format.
Expanded regression tests and security test cases.
Additional custom Semgrep rules.
Improved logging and operational monitoring.
More detailed remediation documentation and risk prioritization.
🤝 Contributing

Contributions, suggestions, and bug reports are welcome.

Fork the repository.
Create a feature branch.
Make changes and add appropriate tests.
Run the test suite and applicable security scans.
Submit a pull request describing the changes and verification performed.

Only use the intentionally vulnerable examples in authorized, controlled educational environments.

⚖️ License

This project is distributed under the MIT License. See LICENSE for the full license text.

👨‍💻 Author

Bejjam Charan Sai Teja

Cybersecurity enthusiast focused on secure coding, application security, vulnerability analysis, and security testing.

GitHub: @charansaiteja-cloud
Repository: CodeAlpha_SecureCodeReview

Built as part of the CodeAlpha Cybersecurity Internship to demonstrate secure development practices and practical application security testing.
