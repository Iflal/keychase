# Code updated by Iflal on 2025-07-17 10:19:18 UTC
import streamlit as st
import base64
import re
import time
import requests
from io import StringIO
# test update for github
class GitHubAPIScanner:
    """
    A class to scan a specific branch in a GitHub repository for potential API leaks.
    Includes case-insensitive, smart file detection and .gitignore awareness.
    """
    API_URL = "https://api.github.com"
    DEFAULT_PATTERNS = {
        "AWS Access Key": r"AKIA[0-9A-Z]{16}",
        "Google API Key": r"AIza[0-9A-Za-z\-_]{35}",
        "Slack Token": r"xox[p|b|o|a]-[0-9a-zA-Z]{10,48}",
        "Generic Password": r"(?i)(password|pwd|secret|token)\s*[:=]\s*['\"][^'\"]+['\"]",
        "GitHub Token": r"ghp_[a-zA-Z0-9]{36}"
    }
    FILE_EXTENSIONS = ('.py', '.js', '.json', '.yml', '.yaml', '.conf', '.cfg', '.php', '.txt', '.env', '.sh', '.bash', '.ps1', '.md', '.html', '.css', '.xml', '.sql', '.go', '.rb', '.java', '.c', '.cpp', '.cs', '.rs', '.swift', '.kt')
    SENSITIVE_FILENAME_KEYWORDS = ('.env', 'config', 'credential', 'secret', 'key')
    EXCLUDED_DIRS = ('node_modules', 'vendor', '.git')

    def __init__(self, token, repo, branch=None, custom_patterns_str=None, logger=None):
        self.token = token
        if '/' not in repo:
            raise ValueError("Repository format must be 'owner/repo'")
        self.owner, self.repo_name = repo.split('/')
        self.branch = branch
        self.target_branch = None # Will be determined before scanning
        self.headers = {
            "Authorization": f"token {self.token}",
            "Accept": "application/vnd.github.v3+json"
        }
        self.patterns = self._load_patterns(custom_patterns_str)
        self.leaks = []
        self.logger = logger if logger else print
        self.ignored_patterns = set()
        self.scanned_files_paths = set()

    def _load_patterns(self, custom_patterns_str):
        # (This method remains unchanged)
        patterns = self.DEFAULT_PATTERNS.copy()
        if custom_patterns_str:
            try:
                for i, line in enumerate(StringIO(custom_patterns_str)):
                    line = line.strip()
                    if line and not line.startswith('#'):
                        patterns[f"Custom Pattern #{i+1}"] = line
            except Exception as e:
                self.logger(f"⚠️ Warning: Error reading custom patterns: {e}")
        return patterns

    def _make_request(self, url, params=None):
        # (This method is updated to accept query parameters)
        while True:
            try:
                response = requests.get(url, headers=self.headers, params=params)
                response.raise_for_status()
                return response
            except requests.exceptions.HTTPError as e:
                if e.response.status_code == 429:
                    self.logger("⏳ Rate limit exceeded. Waiting for 5 seconds...")
                    time.sleep(5)
                    continue
                elif e.response.status_code == 401:
                    raise ConnectionError("Authentication failed. Check your GitHub token.")
                elif e.response.status_code == 404 and "contents" in url:
                    return None
                elif e.response.status_code == 404:
                    raise ConnectionError(f"Repository '{self.owner}/{self.repo_name}' or branch '{self.branch}' not found.")
                else:
                    raise
            except requests.exceptions.RequestException as e:
                raise ConnectionError(f"Network error: {e}")

    def _determine_target_branch(self):
        """Determines the branch to scan, fetching the default if none is specified."""
        if self.branch:
            self.target_branch = self.branch
            self.logger(f"ℹ️ Target branch specified: **{self.target_branch}**")
        else:
            self.logger("ℹ️ No branch specified, fetching repository's default branch...")
            repo_url = f"{self.API_URL}/repos/{self.owner}/{self.repo_name}"
            response = self._make_request(repo_url)
            if response:
                self.target_branch = response.json().get('default_branch', 'main')
                self.logger(f"✅ Default branch is **{self.target_branch}**.")
            else:
                # Fallback in case of an issue
                self.target_branch = 'main'
                self.logger(f"⚠️ Could not determine default branch, falling back to **{self.target_branch}**.")

    def _fetch_gitignore(self):
        gitignore_url = f"{self.API_URL}/repos/{self.owner}/{self.repo_name}/contents/.gitignore"
        response = self._make_request(gitignore_url, params={'ref': self.target_branch})
        if response and response.status_code == 200:
            content = base64.b64decode(response.json()['content']).decode('utf-8')
            for line in content.splitlines():
                stripped_line = line.strip()
                if stripped_line and not stripped_line.startswith('#'):
                    self.ignored_patterns.add(stripped_line)
            self.logger(f"ℹ️ Found and parsed `.gitignore` from branch `{self.target_branch}`.")

    def _should_scan_file(self, filename):
        # (This method remains unchanged)
        filename_lower = filename.lower()
        if filename_lower.endswith(self.FILE_EXTENSIONS):
            return True, "standard extension"
        for keyword in self.SENSITIVE_FILENAME_KEYWORDS:
            if keyword in filename_lower:
                return True, f"sensitive keyword ('{keyword}')"
        return False, None

    def _get_repo_files(self, path=''):
        contents_url = f"{self.API_URL}/repos/{self.owner}/{self.repo_name}/contents/{path}"
        response = self._make_request(contents_url, params={'ref': self.target_branch})
        if not response: return []
        
        files_and_dirs = response.json()
        files_to_scan = []
        for item in files_and_dirs:
            if item['type'] == 'file':
                should_scan, reason = self._should_scan_file(item['name'])
                if should_scan:
                    files_to_scan.append((item, reason))
                    self.scanned_files_paths.add(item['path'])
            elif item['type'] == 'dir' and item['name'] not in self.EXCLUDED_DIRS:
                self.logger(f"📁 Traversing directory: {item['path']}")
                files_to_scan.extend(self._get_repo_files(item['path']))
        return files_to_scan

    def _scan_file_content(self, file_item):
        # (This method remains unchanged)
        content_response = self._make_request(file_item['url'])
        if not content_response: return
        file_data = content_response.json()
        if 'content' not in file_data: return
        try:
            decoded_content = base64.b64decode(file_data['content']).decode('utf-8')
        except UnicodeDecodeError: return
        for line_num, line in enumerate(decoded_content.splitlines(), 1):
            for pattern_name, pattern in self.patterns.items():
                if re.search(pattern, line):
                    leak = {"file_path": file_item['path'], "line": line_num, "pattern_name": pattern_name, "snippet": line.strip()}
                    self.leaks.append(leak)
                    self.logger(f"  🚨 Found potential leak in **{leak['file_path']}:{leak['line']}**")

    def scan_repository(self):
        self._determine_target_branch()
        self.logger(f"🚀 Starting scan on repository: **{self.owner}/{self.repo_name}** (Branch: **{self.target_branch}**)")
        self._fetch_gitignore()
        
        files_to_scan_with_reason = self._get_repo_files()
        total_files = len(files_to_scan_with_reason)
        self.logger(f"✅ Found **{total_files}** files to scan.")

        if total_files > 0:
            progress_bar = st.progress(0)
            for i, (file_item, reason) in enumerate(files_to_scan_with_reason):
                self.logger(f"📄 Scanning file {i+1}/{total_files}: `{file_item['path']}` (Reason: {reason})")
                self._scan_file_content(file_item)
                progress_bar.progress((i + 1) / total_files)
        
        self.logger("🏁 Scan complete.")

def main():
    st.set_page_config(page_title="GitHub API Leak Scanner", page_icon="🛡️")
    st.title("🛡️ GitHub API Leak Scanner")
    st.write("A tool to scan a specific branch in a GitHub repository for accidental API key leaks.")

    with st.form("scan_form"):
        st.header("Scan Configuration")
        repo = st.text_input("GitHub Repository", placeholder="owner/repository-name", help="The repository to scan in `owner/repo` format.")
        token = st.text_input("GitHub Personal Access Token", type="password", help="A PAT with `repo` scope to access the repository.")
        branch = st.text_input("Branch Name (Optional)", placeholder="main", help="Specify a branch to scan. If left empty, the repository's default branch will be used.")
        
        with st.expander("Custom Regex Patterns (Optional)"):
            custom_patterns = st.text_area("Patterns", placeholder="one-regex-pattern-per-line", height=150)
        
        submitted = st.form_submit_button("Scan Repository")

    if submitted:
        if not repo or not token:
            st.error("Repository and GitHub Token are required.")
        else:
            log_container = st.expander("Scan Log", expanded=True)
            report_container = st.container()
            
            def ui_logger(message):
                log_container.info(message)

            with st.spinner("Scanning... This may take a few moments."):
                try:
                    scanner = GitHubAPIScanner(token=token, repo=repo, branch=branch, custom_patterns_str=custom_patterns, logger=ui_logger)
                    scanner.scan_repository()

                    report_container.header(f"Scan Report for `{scanner.owner}/{scanner.repo_name}` on branch `{scanner.target_branch}`")
                    
                    if ".env" in scanner.ignored_patterns and not any('.env' in p.lower() for p in scanner.scanned_files_paths):
                         report_container.info("💡 **Note:** Files named `.env` are listed in the repository's `.gitignore`. This is a good security practice.")

                    if not scanner.leaks:
                        report_container.success(f"✅ No potential leaks found.")
                    else:
                        report_container.warning(f"🚨 Found **{len(scanner.leaks)}** potential leaks:")
                        for leak in scanner.leaks:
                            with report_container.container():
                                st.markdown(f"- **File:** `{leak['file_path']}` (Line: {leak['line']})")
                                st.markdown(f"  - **Pattern:** {leak['pattern_name']}")
                                st.markdown(f"  - **Snippet:**")
                                st.code(leak['snippet'], language='text')
                    
                    report_container.info("Security Advisory: Please handle this report securely and rotate any leaked credentials immediately.")

                except (ValueError, ConnectionError) as e:
                    st.error(f"Error: {e}")
                except Exception as e:
                    st.error(f"An unexpected error occurred: {e}")

if __name__ == "__main__":
    main()