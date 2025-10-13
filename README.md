<p align="right">[简体中文](README.zh-CN.md)</p>

# CodeSentinel: AI-Powered Code Security Auditor

CodeSentinel is an advanced, AI-powered security auditing tool for Python. It uses a hybrid approach, combining local static analysis (AST, Taint Analysis) with powerful AI models (like GPT-4o-mini) to provide deep, accurate vulnerability detection. It's a command-line tool designed to help developers identify and fix security issues before they reach production.

## Key Features

-   **Hybrid Analysis Engine**: Combines the speed of local Abstract Syntax Tree (AST) and Taint Analysis with the deep contextual understanding of AI models.
-   **Multiple Analyzer Modes**: Choose between `local`, `ai`, or `hybrid` analysis modes to fit your needs for speed and accuracy.
-   **Comprehensive Vulnerability Detection**: Identifies a wide range of security vulnerabilities, including:
    -   SQL Injection
    -   Command Injection
    -   Cross-Site Scripting (XSS)
    -   Insecure Deserialization
    -   Hardcoded Secrets & Keys
    -   Weak Cryptography
    -   Path Traversal
-   **Multi-Format Reporting**: Generates clear and actionable reports in various formats: `console`, `markdown`, `json`, `html`, and `xml`.
-   **Intelligent Caching**: Caches results of unchanged files to significantly speed up subsequent scans.
-   **User-Friendly CLI**: A rich command-line interface with extensive options for a tailored analysis experience.
-   **Plugin Architecture**: Designed with a plugin manager to allow for future extensions of detectors and reporters.

## Requirements

-   Python 3.10+
-   An OpenAI API key (for `ai` and `hybrid` modes).

## Installation

1.  **Clone the repository:**
    ```bash
    git clone https://github.com/superFRANK666/CodeSentinel.git
    cd CodeSentinel
    ```

2.  **Create and activate a virtual environment (recommended):**
    ```bash
    # For Windows
    python -m venv venv
    venv\Scripts\activate

    # For macOS/Linux
    python3 -m venv venv
    source venv/bin/activate
    ```

3.  **Install dependencies:**
    ```bash
    pip install -r requirements.txt
    ```

4.  **Set up your environment variables:**
    -   Copy the example `.env.example` file from the `docs` directory to the project root and rename it to `.env`.
    -   Open the `.env` file and add your OpenAI API key:
        ```
        OPENAI_API_KEY=your-openai-api-key-here
        ```

## Usage

CodeSentinel is run from the command line. Here are some common usage examples:

**1. Analyze a single file:**
```bash
python main.py path/to/your/file.py
```

**2. Analyze an entire directory:**
```bash
python main.py src/
```

**3. Generate a specific report format:**
```bash
# Generate a Markdown report
python main.py src/ --output report.md --format markdown

# Generate an HTML report
python main.py src/ --output report.html --format html
```

**4. Use a specific analyzer:**
```bash
# Use the fast local analyzer only
python main.py src/ --analyzer local

# Use the AI analyzer for a deep scan
python main.py src/ --analyzer ai
```

**5. Filter by severity and show progress:**
```bash
python main.py src/ --severity high --progress
```

**6. Get help on all commands:**
```bash
python main.py --help
```

## Project Structure

The project is organized into a clean, layered architecture:

```
CodeSentinel/
├── config/                # Default configuration files
├── docs/                  # Documentation and examples
├── src/
│   ├── application/       # Core application logic (analyzers, report generators)
│   ├── core/              # Core components (interfaces, container, base classes)
│   └── infrastructure/    # Supporting modules (config, cache, UI, etc.)
├── .gitignore
├── main.py                # Main CLI entry point
├── requirements.txt       # Project dependencies
└── .env                   # Environment variables (you create this)
```

## Configuration

-   **Environment Variables**: The primary way to configure secrets like the OpenAI API key is through the `.env` file in the project root.
-   **JSON Configuration**: Default behaviors (like analyzer settings, report formats, etc.) are defined in `config/default.json`. You can create a custom `config.json` to override these settings.

## Contributing

Contributions are welcome! If you'd like to contribute, please follow these steps:

1.  Fork the repository.
2.  Create a new branch (`git checkout -b feature/your-feature`).
3.  Make your changes and commit them (`git commit -m 'Add some feature'`).
4.  Push to the branch (`git push origin feature/your-feature`).
5.  Open a Pull Request.

## License

This project is licensed under the MIT License.