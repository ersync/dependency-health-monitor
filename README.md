# Dependency Health Monitor

A powerful Ruby tool that scans GitHub repositories for dependency issues, identifies vulnerabilities, and 
calculates health scores.

## Features

- Scans repositories for dependency issues (individual, user-owned, or organization-wide)
- Supports multiple package managers:
  - npm/yarn (JavaScript/Node.js)
  - bundler (Ruby)
  - pip (Python)
- Identifies security vulnerabilities with severity levels
- Detects outdated dependencies
- Calculates health scores for each repository
- Provides color-coded terminal reports
- Option to export JSON reports

## Installation

```bash
# Clone the repository
git clone https://github.com/yourusername/dependency-health-monitor.git
cd dependency-health-monitor

# Install required gems
gem install octokit terminal-table colorize faraday-retry
```

## Usage

### Quick Start

```bash
# Using GitHub token as argument
ruby dep_health.rb --token YOUR_GITHUB_TOKEN

# Using GitHub token from environment variable
export GITHUB_TOKEN=your_token_here
ruby dep_health.rb
```

### Common Use Cases

Scan your repositories:
```bash
ruby dep_health.rb --token YOUR_TOKEN
```

Scan an organization's repositories:
```bash
ruby dep_health.rb --token YOUR_TOKEN --org your-organization
```

Scan a specific user's repositories:
```bash
ruby dep_health.rb --token YOUR_TOKEN --user username
```

Scan a single repository:
```bash
ruby dep_health.rb --token YOUR_TOKEN --repo owner/repository
```

### Options

| Option | Description |
|--------|-------------|
| `-t, --token TOKEN` | GitHub token (can also use GITHUB_TOKEN env var) |
| `-u, --user USERNAME` | GitHub username to scan repositories for |
| `-o, --org ORGANIZATION` | GitHub organization to scan repositories for |
| `-r, --repo REPOSITORY` | Single repository (format: owner/repo) |
| `-m, --max MAX` | Maximum repositories to scan (default: 10) |
| `-f, --file FILENAME` | Output JSON report to file |
| `-v, --verbose` | Enable verbose output |
| `-h, --help` | Show help message |

## Requirements

- Ruby 3.x+
- Git installed and in PATH
- For full functionality:
  - npm (for Node.js projects)
  - bundler (for Ruby projects)
  - pip (for Python projects)

## Example Output

```
~/projects/dependency-health-monitor main ❯ ./dep_health.rb --repo devteam/web-dashboard
Successfully installed faraday-retry-2.3.1
1 gem installed
Found 1 repository. Scanning up to 1 repository...

Dependency Health Summary
+-----------------------+----------+-------+-----------------+----------+
| Repository            | Language | Score | Vulnerabilities | Outdated |
+-----------------------+----------+-------+-----------------+----------+
| devteam/web-dashboard | Vue      | 68    | 2               | 8        |
+-----------------------+----------+-------+-----------------+----------+

Issues in devteam/web-dashboard (Score: 68)
+---------------+---------------------------+----------+--------------------------------+
| Type          | Package                   | Severity | Message                        |
+---------------+---------------------------+----------+--------------------------------+
| Vulnerability | lodash                    | high     | Prototype Pollution            |
| Vulnerability | axios                     | medium   | Server-Side Request Forgery    |
| Outdated      | @types/node               | N/A      | Update from 18.0.0 to 20.5.1   |
| Outdated      | typescript                | N/A      | Update from 4.9.5 to 5.2.2     |
| Outdated      | vue                       | N/A      | Update from 3.2.45 to 3.3.4    |
| Outdated      | vite                      | N/A      | Update from 4.0.4 to 4.4.9     |
| Outdated      | eslint                    | N/A      | Update from 8.33.0 to 8.47.0   |
| Outdated      | tailwindcss               | N/A      | Update from 3.2.4 to 3.3.3     |
| Outdated      | jest                      | N/A      | Update from 29.3.1 to 29.6.2   |
| Outdated      | postcss                   | N/A      | Update from 8.4.21 to 8.4.28   |
+---------------+---------------------------+----------+--------------------------------+
```

In actual output, the scores and vulnerability counts are color-coded for better visibility:
- High scores (90-100) appear in green
- Medium scores (70-89) appear in yellow
- Low scores (<70) appear in red
- Zero vulnerabilities/outdated dependencies appear in green
- Any vulnerabilities or outdated dependencies appear in red or yellow

## License

MIT License. See LICENSE file for details.

## Contributing

Contributions are welcome! Please open an issue or pull request for any improvements.
