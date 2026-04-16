import argparse
import base64
import re
import time
import requests

class GitHubAPIScanner:
    """
    A class to scan a GitHub repository for potential API leaks.
    """
    API_URL = "https://api.github.com"
    DEFAULT_PATTERNS = {
        "AWS Access Key": r"AKIA[0-9A-Z]{16}",
        "Google API Key": r"AIza[0-9A-Za-z\-_]{35}",
        "Slack Token": r"xox[p|b|o|a]-[0-9a-zA-Z]{10,48}",
        "Generic Password": r"(?i)(password|pwd|secret|token)\s*[:=]\s*['\"][^'\"]+['\"]",
        "GitHub Token": r"ghp_[a-zA-Z0-9]{36}"
    }
    FILE_EXTENSIONS = ('.py', '.js', '.json', '.yml', '.yaml', '.env', '.conf', '.cfg')
    EXCLUDED_DIRS = ('node_modules', 'vendor', '.git')

    def __init__(self, token, repo, patterns_file=None):
        """
        Initializes the scanner.
        
        :param token: GitHub personal access token.
        :param repo: Repository in 'owner/repo' format.
        :param patterns_file: Optional path to a file with custom regex patterns.
        """
        self.token = token
        if '/' not in repo:
            raise ValueError("Repository format must be 'owner/repo'")
        self.owner, self.repo_name = repo.split('/')
        self.headers = {
            "Authorization": f"token {self.token}",
            "Accept": "application/vnd.github.v3+json"
        }
        self.patterns = self._load_patterns(patterns_file)
        self.leaks = []

    def _load_patterns(self, patterns_file):
        """Loads default and custom regex patterns."""
        patterns = self.DEFAULT_PATTERNS.copy()
        if patterns_file:
            try:
                with open(patterns_file, 'r') as f:
                    for i, line in enumerate(f):
                        line = line.strip()
                        if line and not line.startswith('#'):
                            patterns[f"Custom Pattern #{i+1}"] = line
            except FileNotFoundError:
                print(f"Warning: Custom patterns file not found at {patterns_file}")
            except Exception as e:
                print(f"Warning: Error reading custom patterns file: {e}")
        return patterns

    def _make_request(self, url):
        """
        Makes a request to the GitHub API, handling rate limiting.
        """
        while True:
            try:
                response = requests.get(url, headers=self.headers)
                response.raise_for_status()
                return response
            except requests.exceptions.HTTPError as e:
                if e.response.status_code == 429:
                    print("Rate limit exceeded. Waiting for 5 seconds...")
                    time.sleep(5)
                    continue
                elif e.response.status_code == 401:
                    raise ConnectionError("Authentication failed. Check your GitHub token.")
                elif e.response.status_code == 404:
                    raise ConnectionError(f"Repository '{self.owner}/{self.repo_name}' not found.")
                else:
                    raise
            except requests.exceptions.RequestException as e:
                raise ConnectionError(f"Network error: {e}")

    def _get_repo_files(self, path=''):
        """
        Recursively fetches files from the repository that match the desired extensions.
        """
        contents_url = f"{self.API_URL}/repos/{self.owner}/{self.repo_name}/contents/{path}"
        response = self._make_request(contents_url)
        files_and_dirs = response.json()
        
        files_to_scan = []
        for item in files_and_dirs:
            if item['type'] == 'file' and item['name'].endswith(self.FILE_EXTENSIONS):
                files_to_scan.append(item)
            elif item['type'] == 'dir' and item['name'] not in self.EXCLUDED_DIRS:
                print(f"Scanning directory: {item['path']}")
                files_to_scan.extend(self._get_repo_files(item['path']))
        return files_to_scan

    def _scan_file_content(self, file_item):
        """
        Scans the content of a single file for leaks.
        """
        content_response = self._make_request(file_item['url'])
        file_data = content_response.json()

        if 'content' not in file_data:
            return

        try:
            decoded_content = base64.b64decode(file_data['content']).decode('utf-8')
        except UnicodeDecodeError:
            # Skip binary or non-UTF-8 files
            return

        for line_num, line in enumerate(decoded_content.splitlines(), 1):
            for pattern_name, pattern in self.patterns.items():
                if re.search(pattern, line):
                    leak = {
                        "file_path": file_item['path'],
                        "line": line_num,
                        "pattern_name": pattern_name,
                        "snippet": line.strip()
                    }
                    self.leaks.append(leak)
                    print(f"  -> Found potential leak in {leak['file_path']}:{leak['line']}")


    def scan_repository(self):
        """
        Orchestrates the repository scanning process.
        """
        print(f"Scanning repository: {self.owner}/{self.repo_name}")
        
        try:
            files_to_scan = self._get_repo_files()
            total_files = len(files_to_scan)
            print(f"Found {total_files} files to scan.")

            for i, file_item in enumerate(files_to_scan):
                print(f"Scanning file {i+1}/{total_files}: {file_item['path']}")
                self._scan_file_content(file_item)
        except ConnectionError as e:
            print(f"Error: {e}")
            return

    def generate_report(self):
        """
        Generates and prints the final report.
        """
        print("\n--- Scan Report ---")
        if not self.leaks:
            print(f"No potential leaks found in {self.owner}/{self.repo_name}.")
        else:
            print(f"Found {len(self.leaks)} potential leaks in {self.owner}/{self.repo_name}:\n")
            for leak in self.leaks:
                print(f"- File:    {leak['file_path']}")
                print(f"  Line:    {leak['line']}")
                print(f"  Pattern: {leak['pattern_name']}")
                print(f"  Snippet: \"{leak['snippet']}\"\n")
        
        print("--- End of Report ---")
        print("\nSecurity Advisory: Please handle this report securely as it may contain sensitive information.")


def main():
    parser = argparse.ArgumentParser(description="Scan a GitHub repository for API leaks.")
    parser.add_argument("--token", required=True, help="GitHub personal access token (scope: repo).")
    parser.add_argument("--repo", required=True, help="Target repository in 'owner/repo' format.")
    parser.add_argument("--patterns", help="Optional path to a file with custom regex patterns (one per line).")

    args = parser.parse_args()

    try:
        scanner = GitHubAPIScanner(token=args.token, repo=args.repo, patterns_file=args.patterns)
        scanner.scan_repository()
        scanner.generate_report()
    except (ValueError, ConnectionError) as e:
        print(f"Error: {e}")
    except Exception as e:
        print(f"An unexpected error occurred: {e}")

if __name__ == "__main__":
    main()