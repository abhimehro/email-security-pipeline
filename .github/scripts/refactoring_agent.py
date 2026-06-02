#!/usr/bin/env python3
"""
Custom PR Refactoring Agent using CodeScene API + Google Gemini
Leverages CodeScene's REST API for code health analysis and Google Gemini for refactoring suggestions.
"""

import os
import json
import sys
import argparse
import subprocess
from pathlib import Path
from typing import Optional, Dict, Any
import requests
import tempfile
import time

try:
    import google.generativeai as genai
except ImportError:
    print("ERROR: google-generativeai not installed. Install with: pip install google-generativeai")
    sys.exit(1)


class CodeSceneRefactoringAgent:
    """Main agent for PR refactoring using CodeScene + Gemini."""
    
    def __init__(
        self,
        codescene_token: str,
        google_api_key: str,
        github_token: str,
        codescene_url: str = "https://api.codescene.io/v2",
        repository: str = "",
        pr_number: int = 0,
    ):
        self.codescene_token = codescene_token
        self.google_api_key = google_api_key
        self.github_token = github_token
        self.codescene_url = codescene_url
        self.repository = repository
        self.pr_number = pr_number
        self.project_id = None
        
        # Configure Gemini
        genai.configure(api_key=google_api_key)
        self.gemini_model = genai.GenerativeModel('gemini-2.0-flash-exp')
        
        # Set up headers for CodeScene API
        self.cs_headers = {
            "Authorization": f"Bearer {codescene_token}",
            "Accept": "application/json",
        }
        
    def log(self, level: str, message: str):
        """Structured logging with GitHub Actions support."""
        timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
        if level == "ERROR":
            print(f"::error::{message}")
        elif level == "WARNING":
            print(f"::warning::{message}")
        elif level == "INFO":
            print(f"[{timestamp}] ℹ️  {message}")
        elif level == "SUCCESS":
            print(f"[{timestamp}] ✅ {message}")
        else:
            print(f"[{timestamp}] {message}")
    
    def find_project_by_repo(self, repo_url: str) -> Optional[int]:
        """Find CodeScene project ID by repository URL."""
        self.log("INFO", f"Looking up project for repo: {repo_url}")
        
        try:
            response = requests.get(
                f"{self.codescene_url}/projects",
                headers=self.cs_headers,
                params={"page": 1, "page_size": 100}
            )
            response.raise_for_status()
            
            projects = response.json()
            for project in projects.get("projects", []):
                # Check if any repository in the project matches
                if repo_url in project.get("repositories", []):
                    self.log("SUCCESS", f"Found project: {project['name']} (ID: {project['id']})")
                    return project["id"]
            
            self.log("WARNING", f"No project found for repo: {repo_url}")
            return None
            
        except requests.exceptions.RequestException as e:
            self.log("ERROR", f"Failed to list projects: {e}")
            return None
    
    def get_latest_analysis(self, project_id: int) -> Optional[Dict[str, Any]]:
        """Fetch the latest code health analysis for a project."""
        self.log("INFO", f"Fetching latest analysis for project {project_id}")
        
        try:
            response = requests.get(
                f"{self.codescene_url}/projects/{project_id}/analyses/latest",
                headers=self.cs_headers
            )
            response.raise_for_status()
            analysis = response.json()
            
            self.log("SUCCESS", f"Analysis retrieved (ID: {analysis.get('id')})")
            return analysis
            
        except requests.exceptions.RequestException as e:
            self.log("ERROR", f"Failed to fetch analysis: {e}")
            return None
    
    def get_technical_debt_hotspots(self, project_id: int) -> list:
        """Get technical debt hotspots from the latest analysis."""
        self.log("INFO", "Fetching technical debt hotspots")
        
        try:
            response = requests.get(
                f"{self.codescene_url}/projects/{project_id}/analyses/latest/technical-debt",
                headers=self.cs_headers,
                params={"refactoring_targets": "true"}
            )
            response.raise_for_status()
            
            debt = response.json()
            hotspots = debt.get("hotspots", [])
            self.log("INFO", f"Found {len(hotspots)} hotspots to address")
            
            return hotspots[:5]  # Return top 5 hotspots
            
        except requests.exceptions.RequestException as e:
            self.log("ERROR", f"Failed to fetch technical debt: {e}")
            return []
    
    def get_files_by_health(self, project_id: int, limit: int = 10) -> list:
        """Get files with lowest code health scores."""
        self.log("INFO", "Fetching files sorted by code health")
        
        try:
            response = requests.get(
                f"{self.codescene_url}/projects/{project_id}/analyses/latest/files",
                headers=self.cs_headers,
                params={
                    "page": 1,
                    "page_size": limit,
                    "order_by": "code_health",
                    "fields": "path,code_health,lines_of_code"
                }
            )
            response.raise_for_status()
            
            files = response.json().get("files", [])
            self.log("INFO", f"Retrieved {len(files)} files for analysis")
            
            return files
            
        except requests.exceptions.RequestException as e:
            self.log("ERROR", f"Failed to fetch files: {e}")
            return []
    
    def read_file_content(self, file_path: str, max_lines: int = 100) -> str:
        """Read file content with line limit for context."""
        try:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                lines = f.readlines()[:max_lines]
                return "".join(lines)
        except Exception as e:
            self.log("WARNING", f"Could not read {file_path}: {e}")
            return ""
    
    def generate_refactoring_suggestion(
        self,
        file_path: str,
        code_health: float,
        hotspot_analysis: str = ""
    ) -> str:
        """Use Gemini to generate refactoring suggestions."""
        self.log("INFO", f"Generating refactoring suggestions for {file_path}")
        
        try:
            file_content = self.read_file_content(file_path)
            
            if not file_content:
                self.log("WARNING", f"Could not read file content: {file_path}")
                return ""
            
            prompt = f"""You are an expert code refactoring assistant guided by Code Health metrics.

FILE: {file_path}
CURRENT CODE HEALTH SCORE: {code_health}/10.0
{f'HOTSPOT ANALYSIS: {hotspot_analysis}' if hotspot_analysis else ''}

TASK: Analyze this code and provide specific, actionable refactoring suggestions to improve:
1. Code Health (maintainability, complexity, readability)
2. Reduce technical debt
3. Improve testability

GUIDELINES:
- Focus on high-impact changes that improve maintainability
- Keep suggestions practical and implementable
- Prioritize reducing cyclomatic complexity and improving cohesion
- Suggest concrete code improvements, not just concepts

CODE:
```
{file_content}
```

Provide:
1. Current issues (2-3 main problems)
2. Specific refactoring recommendations (with code examples if possible)
3. Expected improvement in Code Health

Be concise and actionable."""
            
            response = self.gemini_model.generate_content(prompt)
            suggestion = response.text
            
            self.log("SUCCESS", f"Refactoring suggestion generated for {file_path}")
            return suggestion
            
        except Exception as e:
            self.log("ERROR", f"Failed to generate suggestion: {e}")
            return ""
    
    def create_pr_comment(self, suggestions: Dict[str, str]) -> str:
        """Format suggestions as a GitHub PR comment."""
        comment_body = """## 🔬 CodeScene PR Refactoring Agent Analysis

### Code Health Insights & Refactoring Recommendations

"""
        
        for file_path, suggestion in suggestions.items():
            comment_body += f"### 📄 `{file_path}`\n\n{suggestion}\n\n---\n\n"
        
        comment_body += """### 📊 Next Steps
1. Review the refactoring suggestions above
2. Apply changes as needed to improve Code Health
3. Run your test suite to ensure no regressions
4. Commit improvements and re-request review

---
Generated by [CodeScene Refactoring Agent](https://github.com/abhimehro/email-security-pipeline) • Code Health Guided Refactoring"""
        
        return comment_body
    
    def post_github_comment(self, comment_body: str) -> bool:
        """Post analysis results as a GitHub PR comment."""
        if not self.pr_number or not self.repository:
            self.log("WARNING", "PR context not available, skipping comment")
            return False
        
        try:
            owner, repo = self.repository.split("/")
            url = f"https://api.github.com/repos/{owner}/{repo}/issues/{self.pr_number}/comments"
            
            headers = {
                "Authorization": f"token {self.github_token}",
                "Accept": "application/vnd.github.v3+json",
            }
            
            response = requests.post(
                url,
                json={"body": comment_body},
                headers=headers
            )
            response.raise_for_status()
            
            self.log("SUCCESS", "Posted comment to PR")
            return True
            
        except requests.exceptions.RequestException as e:
            self.log("ERROR", f"Failed to post GitHub comment: {e}")
            return False
    
    def run(self, command: str = "skill:fix-code-health-degradations") -> bool:
        """Main workflow orchestration."""
        self.log("INFO", "=== CodeScene PR Refactoring Agent Started ===")
        self.log("INFO", f"Command: {command}")
        self.log("INFO", f"Repository: {self.repository}")
        
        # Step 1: Find project
        if not self.project_id:
            # Try to construct repo URL from GitHub
            if self.repository:
                repo_url = f"https://github.com/{self.repository}.git"
                self.project_id = self.find_project_by_repo(repo_url)
                
                if not self.project_id:
                    self.log("ERROR", "Could not find CodeScene project for this repository")
                    return False
        
        # Step 2: Get analysis
        analysis = self.get_latest_analysis(self.project_id)
        if not analysis:
            self.log("ERROR", "Failed to retrieve code health analysis")
            return False
        
        overall_health = analysis.get("code_health", {}).get("current_score", 0)
        self.log("INFO", f"Overall Code Health: {overall_health}/10.0")
        
        # Step 3: Get files to improve
        files_to_improve = self.get_files_by_health(self.project_id, limit=3)
        
        if not files_to_improve:
            self.log("WARNING", "No files to analyze")
            return False
        
        # Step 4: Generate suggestions
        suggestions = {}
        hotspots = self.get_technical_debt_hotspots(self.project_id)
        hotspot_summary = "\n".join([f"- {h.get('name', 'Unknown')}: {h.get('reason', '')}" 
                                     for h in hotspots[:3]])
        
        for file_info in files_to_improve:
            file_path = file_info.get("path", "")
            code_health = file_info.get("code_health", {}).get("current_score", 0)
            
            if code_health < 8.0:  # Focus on files with health < 8.0
                suggestion = self.generate_refactoring_suggestion(
                    file_path,
                    code_health,
                    hotspot_summary
                )
                
                if suggestion:
                    suggestions[file_path] = suggestion
        
        if not suggestions:
            self.log("WARNING", "No actionable suggestions generated")
            return True
        
        # Step 5: Create and post PR comment
        comment_body = self.create_pr_comment(suggestions)
        self.post_github_comment(comment_body)
        
        self.log("SUCCESS", "=== Refactoring Agent Completed Successfully ===")
        return True


def main():
    parser = argparse.ArgumentParser(
        description="CodeScene PR Refactoring Agent",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python refactoring_agent.py --pr-number 42 \\
    --repository owner/repo \\
    --command "skill:fix-code-health-degradations"
        """
    )
    
    parser.add_argument(
        "--pr-number",
        type=int,
        default=0,
        help="Pull request number for GitHub comment context"
    )
    parser.add_argument(
        "--repository",
        default=os.getenv("GITHUB_REPOSITORY", ""),
        help="Repository in format owner/repo"
    )
    parser.add_argument(
        "--command",
        default="skill:fix-code-health-degradations",
        help="Refactoring command/skill to execute"
    )
    parser.add_argument(
        "--codescene-token",
        default=os.getenv("CODESCENE_ACCESS_TOKEN", ""),
        help="CodeScene API token (env: CODESCENE_ACCESS_TOKEN)"
    )
    parser.add_argument(
        "--google-api-key",
        default=os.getenv("GOOGLE_API_KEY", ""),
        help="Google API key (env: GOOGLE_API_KEY)"
    )
    parser.add_argument(
        "--github-token",
        default=os.getenv("GITHUB_TOKEN", ""),
        help="GitHub token (env: GITHUB_TOKEN)"
    )
    parser.add_argument(
        "--codescene-url",
        default=os.getenv("CODESCENE_URL", "https://api.codescene.io/v2"),
        help="CodeScene API base URL"
    )
    
    args = parser.parse_args()
    
    # Validate required inputs
    if not args.codescene_token:
        print("ERROR: CODESCENE_ACCESS_TOKEN not provided")
        sys.exit(1)
    
    if not args.google_api_key:
        print("ERROR: GOOGLE_API_KEY not provided")
        sys.exit(1)
    
    if not args.github_token:
        print("ERROR: GITHUB_TOKEN not provided")
        sys.exit(1)
    
    # Initialize and run agent
    agent = CodeSceneRefactoringAgent(
        codescene_token=args.codescene_token,
        google_api_key=args.google_api_key,
        github_token=args.github_token,
        codescene_url=args.codescene_url,
        repository=args.repository,
        pr_number=args.pr_number,
    )
    
    success = agent.run(command=args.command)
    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()
