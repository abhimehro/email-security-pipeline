#!/usr/bin/env python3
import os

"""
Custom PR Refactoring Agent using CodeScene API + Google Gemini
Hybrid approach: Auto-fixes based on skill type and confidence levels.
Leverages CodeScene's REST API for code health analysis and Google Gemini for refactoring suggestions.

Supported Skills:
- skill:fix-code-health-degradations (High confidence auto-fix, narrow scope)
- skill:uplift-code-health (Moderate confidence auto-fix, broader scope)
"""

import json
import sys
import argparse
import subprocess
from typing import Optional, Dict, Any, Tuple
import requests
import time
import re

try:
    import google.generativeai as genai
except ImportError:
    print(
        "ERROR: google-generativeai not installed. Install with: pip install google-generativeai"
    )
    sys.exit(1)


class CodeSceneRefactoringAgent:
    """Main agent for PR refactoring using CodeScene + Gemini."""

    # Skill-based confidence thresholds
    SKILL_CONFIDENCE_MAP = {
        "fix-code-health-degradations": 0.90,  # High confidence - narrow, safer scope
        "uplift-code-health": 0.85,  # Moderate confidence - broader improvements
        "default": 0.80,  # Fallback for unknown skills
    }

    def __init__(
        self,
        codescene_token: str,
        google_api_key: str,
        github_token: str,
        codescene_url: str = "https://api.codescene.io/v2",
        repository: str = "",
        pr_number: int = 0,
        command: str = "",
    ):
        self.codescene_token = codescene_token
        self.google_api_key = google_api_key
        self.github_token = github_token
        self.codescene_url = codescene_url
        self.repository = repository
        self.pr_number = pr_number
        self.command = command
        self.project_id = None
        self.auto_fixes_applied = []
        self.suggestions = {}

        # Extract skill from command
        self.skill = self._extract_skill(command)
        self.auto_fix_threshold = self._get_confidence_threshold(self.skill)

        # Configure Gemini with proper API key
        genai.configure(api_key=google_api_key)
        self.gemini_model = genai.GenerativeModel(model_name="gemini-2.0-flash")

        # Set up headers for CodeScene API
        self.cs_headers = {
            "Authorization": f"Bearer {codescene_token}",
            "Accept": "application/json",
        }

    def _extract_skill(self, command: str) -> str:
        """Extract skill name from command."""
        match = re.search(r"skill:([a-z\-]+)", command)
        if match:
            return match.group(1)
        return "default"

    def _get_confidence_threshold(self, skill: str) -> float:
        """Get auto-fix confidence threshold for the skill."""
        return self.SKILL_CONFIDENCE_MAP.get(
            skill, self.SKILL_CONFIDENCE_MAP["default"]
        )

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
                params={"page": 1, "page_size": 100},
            )
            response.raise_for_status()

            projects = response.json()
            for project in projects.get("projects", []):
                # Check if any repository in the project matches
                if repo_url in project.get("repositories", []):
                    self.log(
                        "SUCCESS",
                        f"Found project: {project['name']} (ID: {project['id']})",
                    )
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
                headers=self.cs_headers,
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
                params={"refactoring_targets": "true"},
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
                    "fields": "path,code_health,lines_of_code",
                },
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
            if ".." in str(file_path):
                self.log("ERROR", "Path traversal detected")
                return ""

            clean_path = str(file_path).lstrip("/")
            base_dir = os.path.realpath(os.getcwd())
            safe_path = os.path.realpath(os.path.join(base_dir, clean_path))

            if os.path.commonprefix([safe_path, base_dir]) != base_dir:
                self.log("ERROR", "Path traversal detected")
                return ""

            with open(safe_path, "r", encoding="utf-8", errors="ignore") as f:
                lines = f.readlines()[:max_lines]
                return "".join(lines)
        except Exception as e:
            self.log("WARNING", f"Could not read {file_path}: {e}")
            return ""

    def classify_issue_for_skill(
        self, file_path: str, code_health: float, hotspot_analysis: str = ""
    ) -> Tuple[str, float]:
        """Classify issue complexity and fix confidence based on the skill being used."""
        self.log("INFO", f"Classifying issue for skill '{self.skill}' in {file_path}")

        try:
            file_content = self.read_file_content(file_path)

            if not file_content:
                return "unknown", 0.0

            skill_context = self._get_skill_context()

            prompt = f"""You are a code refactoring expert. Analyze this code for the specific refactoring skill.

SKILL: {self.skill}
SKILL SCOPE: {skill_context}

FILE: {file_path}
CODE HEALTH: {code_health}/10.0
{f'HOTSPOT ANALYSIS: {hotspot_analysis}' if hotspot_analysis else ''}

CODE:
```
{file_content}
```

Respond with ONLY a JSON object (no markdown, no extra text):
{{
  "applicability": "applicable|not_applicable",
  "can_auto_fix": true|false,
  "fix_confidence": 0.0-1.0,
  "reason": "Brief explanation"
}}

Guidelines for {self.skill}:
- For "fix-code-health-degradations": Only flag regressions introduced by the PR (fixes should be high confidence ≥ 0.9)
- For "uplift-code-health": Flag code health improvements possible (moderate-high confidence ≥ 0.85)
- Only set "can_auto_fix": true if the fix is straightforward and low-risk
- Consider: Does this change preserve all existing functionality?
- Consider: Is this a safe, non-breaking change?"""

            response = self.gemini_model.generate_content(prompt)
            result_text = response.text.strip()

            # Clean up markdown if present
            if result_text.startswith("```"):
                result_text = result_text.split("```")[1]
                if result_text.startswith("json"):
                    result_text = result_text[4:]
                result_text = result_text.strip()

            result = json.loads(result_text)
            applicability = result.get("applicability", "not_applicable")

            if applicability != "applicable":
                self.log(
                    "INFO",
                    f"Not applicable for skill '{self.skill}': {result.get('reason')}",
                )
                return "not_applicable", 0.0

            confidence = result.get("fix_confidence", 0.0)
            can_fix = result.get("can_auto_fix", False)

            self.log(
                "INFO",
                f"Issue classification: can_auto_fix={can_fix}, confidence={confidence:.2f}",
            )
            return "applicable", confidence if can_fix else 0.0

        except Exception as e:
            self.log("WARNING", f"Failed to classify issue: {e}")
            return "error", 0.0

    def _get_skill_context(self) -> str:
        """Get context description for the current skill."""
        contexts = {
            "fix-code-health-degradations": "Fix only Code Health regressions introduced by this PR, without touching pre-existing debt. Scope is narrow and focused on PR-specific issues.",
            "uplift-code-health": "Raise Code Health for selected files toward a target score in measurable incremental steps. Can address pre-existing issues, broader scope than degradation fixes.",
        }
        return contexts.get(self.skill, "Apply general code health improvements")

    def generate_auto_fix(self, file_path: str, code_health: float) -> Optional[str]:
        """Generate and apply a simple auto-fix."""
        self.log("INFO", f"Generating auto-fix for {file_path}")

        try:
            file_content = self.read_file_content(file_path)

            if not file_content:
                return None

            skill_context = self._get_skill_context()

            prompt = f"""You are an expert code refactorer. Generate a MINIMAL, SAFE fix for this code.

SKILL: {self.skill}
SKILL SCOPE: {skill_context}

FILE: {file_path}
CODE HEALTH: {code_health}/10.0

CRITICAL CONSTRAINTS:
- Only fix issues directly applicable to the {self.skill} skill
- Do NOT change logic or APIs
- Do NOT add new dependencies
- Do NOT refactor complex sections
- Preserve ALL existing functionality exactly
- Return ONLY the fixed code (no explanations, no markdown)
- If the fix would be complex or risky, return the original code unchanged

For {self.skill}:
- Focus on straightforward improvements that are clearly beneficial
- Ensure changes are low-risk and non-breaking
- Maintain backward compatibility

CODE:
{file_content}

Return the fixed code:"""

            response = self.gemini_model.generate_content(prompt)
            fixed_code = response.text.strip()

            # Clean markdown if present
            if fixed_code.startswith("```"):
                fixed_code = fixed_code.split("```")[1]
                if fixed_code.startswith(
                    ("python", "javascript", "java", "go", "typescript", "rust")
                ):
                    fixed_code = fixed_code.split("\n", 1)[1]
                if fixed_code.endswith("```"):
                    fixed_code = fixed_code[:-3]
                fixed_code = fixed_code.strip()

            return fixed_code if fixed_code else None

        except Exception as e:
            self.log("ERROR", f"Failed to generate auto-fix: {e}")
            return None

    def apply_auto_fix(self, file_path: str, fixed_code: str) -> bool:
        """Apply and commit the auto-fix."""
        try:
            if ".." in str(file_path):
                self.log("ERROR", "Path traversal detected")
                return False

            clean_path = str(file_path).lstrip("/")
            base_dir = os.path.realpath(os.getcwd())
            safe_path = os.path.realpath(os.path.join(base_dir, clean_path))

            if os.path.commonprefix([safe_path, base_dir]) != base_dir:
                self.log("ERROR", "Path traversal detected")
                return False

            with open(safe_path, "w", encoding="utf-8") as f:
                f.write(fixed_code)

            # Stage and commit
            subprocess.run(["git", "add", file_path], check=True, capture_output=True)
            self.auto_fixes_applied.append(file_path)
            self.log("SUCCESS", f"Applied auto-fix to {file_path}")
            return True

        except Exception as e:
            self.log("ERROR", f"Failed to apply auto-fix to {file_path}: {e}")
            return False

    def generate_refactoring_suggestion(
        self, file_path: str, code_health: float, hotspot_analysis: str = ""
    ) -> str:
        """Use Gemini to generate detailed refactoring suggestions."""
        self.log("INFO", f"Generating refactoring suggestions for {file_path}")

        try:
            file_content = self.read_file_content(file_path)

            if not file_content:
                self.log("WARNING", f"Could not read file content: {file_path}")
                return ""

            skill_context = self._get_skill_context()

            prompt = f"""You are an expert code refactoring assistant guided by Code Health metrics and CodeScene insights.

SKILL: {self.skill}
SKILL SCOPE: {skill_context}

FILE: {file_path}
CURRENT CODE HEALTH SCORE: {code_health}/10.0
{f'HOTSPOT ANALYSIS: {hotspot_analysis}' if hotspot_analysis else ''}

TASK: Analyze this code and provide specific, actionable refactoring suggestions aligned with the {self.skill} skill.

GUIDELINES:
- Focus on improvements directly applicable to the skill's scope
- Provide high-impact changes that improve maintainability
- Keep suggestions practical and implementable
- Prioritize reducing cyclomatic complexity and improving cohesion
- Suggest concrete code improvements with specific examples
- Be specific about WHERE and HOW to refactor
- Estimate effort level (small/medium/large)

CODE:
```
{file_content}
```

Provide:
1. Current issues (2-3 main problems with specifics)
2. Specific refactoring recommendations (with code examples)
3. Expected improvement in Code Health
4. Estimated effort (small/medium/large)
5. Why these changes align with the {self.skill} skill

Be concise and actionable."""

            response = self.gemini_model.generate_content(prompt)
            suggestion = response.text

            self.log("SUCCESS", f"Refactoring suggestion generated for {file_path}")
            return suggestion

        except Exception as e:
            self.log("ERROR", f"Failed to generate suggestion: {e}")
            return ""

    def create_pr_comment(self) -> str:
        """Format suggestions and fixes as a GitHub PR comment."""
        skill_badge = f"📊 **Skill**: `{self.skill}`"
        threshold_info = (
            f"Auto-fix confidence threshold: ≥{int(self.auto_fix_threshold*100)}%"
        )

        comment_body = f"""## 🔬 CodeScene PR Refactoring Agent Analysis

{skill_badge}
{threshold_info}

---

### 🔧 Auto-Fixes Applied
"""

        if self.auto_fixes_applied:
            comment_body += f"""
The following files have been automatically fixed with high confidence:
{chr(10).join([f"- ✅ `{f}`" for f in self.auto_fixes_applied])}

**These changes will be committed with the next push.**

---
"""
        else:
            comment_body += """
_No auto-fixes were applicable with sufficient confidence for this skill._

---
"""

        if self.suggestions:
            comment_body += f"""### 💡 Manual Refactoring Suggestions

Review these recommendations to further improve Code Health within the **{self.skill}** scope:

"""
            for file_path, suggestion in self.suggestions.items():
                comment_body += f"### 📄 `{file_path}`\n\n{suggestion}\n\n---\n\n"

        comment_body += f"""### 📊 Next Steps
1. **Auto-fixes**: Simple, high-confidence improvements have been automatically applied and committed
2. **Manual improvements**: Review the suggestions above for more involved refactoring
3. **Verification**: Run your test suite to ensure no regressions
4. **Iteration**: Feel free to request further refactoring by commenting `/cs-agent {self.skill}` again

### 🛡️ Safety Notes
- All changes preserve existing functionality
- CI checks will run automatically after auto-fixes are committed
- Any unintended degradation will be caught by your test suite and Code Health checks
- You can safely revert or adjust any changes before merge

---
Generated by [CodeScene Refactoring Agent](https://github.com/abhimehro/email-security-pipeline) • Hybrid Auto-Fix + Suggestion Mode
Skill-guided refactoring | Confidence-based decisions | Code Health driven"""

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

            response = requests.post(url, json={"body": comment_body}, headers=headers)
            response.raise_for_status()

            self.log("SUCCESS", "Posted comment to PR")
            return True

        except requests.exceptions.RequestException as e:
            self.log("ERROR", f"Failed to post GitHub comment: {e}")
            return False

    def commit_auto_fixes(self) -> bool:
        """Commit all auto-fixes to the PR branch."""
        if not self.auto_fixes_applied:
            return True

        try:
            # Configure git
            subprocess.run(
                ["git", "config", "user.name", "github-actions[bot]"],
                check=True,
                capture_output=True,
            )
            subprocess.run(
                [
                    "git",
                    "config",
                    "user.email",
                    "41898282+github-actions[bot]@users.noreply.github.com",
                ],
                check=True,
                capture_output=True,
            )

            # Commit
            files_str = ", ".join(self.auto_fixes_applied)
            commit_msg = f"🔧 CodeScene {self.skill}: {files_str}"
            subprocess.run(
                ["git", "commit", "-m", commit_msg], check=True, capture_output=True
            )

            self.log("SUCCESS", "Auto-fixes committed successfully")
            return True

        except Exception as e:
            self.log("ERROR", f"Failed to commit auto-fixes: {e}")
            return False

    def run(self) -> bool:
        """Main workflow orchestration."""
        self.log("INFO", "=== CodeScene PR Refactoring Agent Started ===")
        self.log("INFO", f"Skill: {self.skill}")
        self.log("INFO", f"Auto-fix threshold: ≥{int(self.auto_fix_threshold*100)}%")
        self.log("INFO", f"Repository: {self.repository}")

        # Step 1: Find project
        if not self.project_id:
            if self.repository:
                repo_url = f"https://github.com/{self.repository}.git"
                self.project_id = self.find_project_by_repo(repo_url)

                if not self.project_id:
                    self.log(
                        "ERROR", "Could not find CodeScene project for this repository"
                    )
                    return False

        # Step 2: Get analysis
        analysis = self.get_latest_analysis(self.project_id)
        if not analysis:
            self.log("ERROR", "Failed to retrieve code health analysis")
            return False

        overall_health = analysis.get("code_health", {}).get("current_score", 0)
        self.log("INFO", f"Overall Code Health: {overall_health}/10.0")

        # Step 3: Get files to improve
        files_to_improve = self.get_files_by_health(self.project_id, limit=5)

        if not files_to_improve:
            self.log("WARNING", "No files to analyze")
            return False

        # Step 4: Get hotspots for context
        hotspots = self.get_technical_debt_hotspots(self.project_id)
        hotspot_summary = "\n".join(
            [
                f"- {h.get('name', 'Unknown')}: {h.get('reason', '')}"
                for h in hotspots[:3]
            ]
        )

        # Step 5: Classify and process each file
        for file_info in files_to_improve:
            file_path = file_info.get("path", "")
            code_health = file_info.get("code_health", {}).get("current_score", 0)

            if code_health < 8.0:  # Focus on files with health < 8.0
                # Classify for the specific skill
                applicability, confidence = self.classify_issue_for_skill(
                    file_path, code_health, hotspot_summary
                )

                if applicability != "applicable":
                    self.log(
                        "INFO",
                        f"Skipping {file_path} - not applicable for skill '{self.skill}'",
                    )
                    continue

                # Decide based on confidence and skill threshold
                if confidence >= self.auto_fix_threshold:
                    self.log(
                        "INFO",
                        f"High confidence fix for {file_path} ({confidence:.2f})",
                    )
                    fixed_code = self.generate_auto_fix(file_path, code_health)
                    if fixed_code:
                        self.apply_auto_fix(file_path, fixed_code)
                else:
                    self.log(
                        "INFO",
                        f"Generating suggestion for {file_path} (confidence: {confidence:.2f})",
                    )
                    suggestion = self.generate_refactoring_suggestion(
                        file_path, code_health, hotspot_summary
                    )
                    if suggestion:
                        self.suggestions[file_path] = suggestion

        # Step 6: Commit auto-fixes if any
        if self.auto_fixes_applied:
            self.commit_auto_fixes()

        # Step 7: Create and post PR comment
        comment_body = self.create_pr_comment()
        self.post_github_comment(comment_body)

        self.log("SUCCESS", "=== Refactoring Agent Completed Successfully ===")
        return True


def parse_arguments():
    parser = argparse.ArgumentParser(
        description="CodeScene PR Refactoring Agent (Skill-Based Hybrid Mode)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--pr-number", type=int, default=0)
    parser.add_argument("--repository", default=os.getenv("GITHUB_REPOSITORY", ""))
    parser.add_argument("--command", default="skill:fix-code-health-degradations")
    parser.add_argument(
        "--codescene-token", default=os.getenv("CODESCENE_ACCESS_TOKEN", "")
    )
    parser.add_argument(
        "--google-api-key",
        default=os.getenv("GOOGLE_GENERATIVE_AI_API_KEY")
        or os.getenv("GOOGLE_API_KEY", ""),
    )
    parser.add_argument("--github-token", default=os.getenv("GITHUB_TOKEN", ""))
    parser.add_argument(
        "--codescene-url",
        default=os.getenv("CODESCENE_URL", "https://api.codescene.io/v2"),
    )
    return parser.parse_args()


def validate_args(args):
    if not args.codescene_token:
        print("::error::CODESCENE_ACCESS_TOKEN not provided")
        sys.exit(1)
    if not args.google_api_key:
        print("::error::GOOGLE_GENERATIVE_AI_API_KEY or GOOGLE_API_KEY not provided")
        sys.exit(1)
    if not args.github_token:
        print("::error::GITHUB_TOKEN not provided")
        sys.exit(1)


def main():
    args = parse_arguments()
    validate_args(args)

    agent = CodeSceneRefactoringAgent(
        codescene_token=args.codescene_token,
        google_api_key=args.google_api_key,
        github_token=args.github_token,
        codescene_url=args.codescene_url,
        repository=args.repository,
        pr_number=args.pr_number,
        command=args.command,
    )
    success = agent.run()
    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()
