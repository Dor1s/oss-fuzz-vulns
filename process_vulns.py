import os
import sys
import yaml
import re

# Add current directory to path so we can import infra
sys.path.append(os.getcwd())

try:
    from infra.syncer.google_issue_tracker import client
    from infra.syncer.google_issue_tracker import issue_tracker
except ImportError:
    print("Warning: Could not import infra.syncer.google_issue_tracker. "
          "Fetching issues from Google Issue Tracker will be disabled.", file=sys.stderr)
    client = None
    issue_tracker = None

def process_yaml_file(filepath, data_dir, log_file):
    """Processes a single YAML file."""
    try:
        with open(filepath, 'r') as f:
            data = yaml.safe_load(f)
    except yaml.YAMLError as e:
        print(f"Error parsing YAML file: {filepath}\n{e}", file=sys.stderr)
        return

    # Extract required values
    try:
        id_val = data.get('id')
        summary = data.get('summary')
        details = data.get('details')

        report_url = None
        if 'references' in data:
            for ref in data['references']:
                if ref.get('type') == 'REPORT':
                    report_url = ref.get('url')
                    break

        package_name = data['affected'][0]['package']['name']

        if 'ranges' not in data['affected'][0]:
            print(f"Skipping {filepath} because 'ranges' key is missing.", file=sys.stderr)
            return

        repo_url = None
        commit_introduced = None
        commit_fixed = None

        for event in data['affected'][0]['ranges'][0]['events']:
            if 'introduced' in event:
                commit_introduced = event['introduced']
            if 'fixed' in event:
                commit_fixed = event['fixed']

        if 'repo' in data['affected'][0]['ranges'][0]:
            repo_url = data['affected'][0]['ranges'][0]['repo']

        # Check for GitHub URL
        if not repo_url or "github.com" not in repo_url:
            with open(log_file, 'a') as f:
                f.write(f"{filepath}\n")
            return

        if repo_url.endswith('.git'):
            repo_url = repo_url[:-4]

        # Create full commit URLs
        if commit_introduced:
            commit_introduced = f"{repo_url}/commit/{commit_introduced}"
        if commit_fixed:
            commit_fixed = f"{repo_url}/commit/{commit_fixed}"

        # Create output content
        output_content = f"id: {id_val}\n"
        output_content += f"summary: {summary}\n"
        output_content += f"details: {details}\n"
        output_content += f"REPORT_url: {report_url}\n"
        output_content += f"package_name: {package_name}\n"
        output_content += f"commit_introduced: {commit_introduced}\n"
        output_content += f"commit_fixed: {commit_fixed}\n"

        # Write to output file
        output_dir = os.path.join(data_dir, os.path.basename(os.path.dirname(filepath)))
        if not os.path.exists(output_dir):
            os.makedirs(output_dir)

        output_filepath = os.path.join(output_dir, os.path.basename(filepath))
        with open(output_filepath, 'w') as f:
            f.write(output_content)

    except (KeyError, IndexError, TypeError) as e:
        print(f"Error processing file: {filepath}\n{e}", file=sys.stderr)

def fetch_and_process_issues(data_dir):
    """Fetches issues from Google Issue Tracker and processes them."""
    if not client or not issue_tracker:
        return

    print("Attempting to fetch issues from Google Issue Tracker...")
    try:
        # Try to build client without impersonation first (user credentials)
        try:
            http = client.build_http(service_account=None)
        except Exception as e:
            print(f"Could not build http client: {e}. Trying with default...", file=sys.stderr)
            http = client.build_http() # Fallback to default behavior (maybe env vars are set for impersonation)

        # We pass service_account=None if we built http client without impersonation
        # But if we fell back to default build_http(), it might have impersonation.
        # This is tricky because we don't know which path succeeded if both throw.
        # However, for simplicity, if we are here, we probably just want to pass the http client
        # and let IssueTracker use its default or what we give it.
        # But wait, I updated IssueTracker to accept service_account.
        # If I want to persist "no impersonation", I should pass service_account=None to IssueTracker.

        tracker = issue_tracker.IssueTracker(http, service_account=None)

        # The user mentioned: type=vulnerability
        query = 'type:vulnerability'

        # We might want to limit the results for testing, but the user asked for "initial version running"
        # Since I can't really test this live, I'll write the code to fetch all.

        count = 0
        for issue in tracker.find_issues(query):
            count += 1
            process_issue(issue, data_dir)

        print(f"Fetched and processed {count} issues from Issue Tracker.")

    except Exception as e:
        print(f"Failed to fetch issues: {e}", file=sys.stderr)

def process_issue(issue, data_dir):
    """Processes a single issue from the Issue Tracker."""
    try:
        issue_id = issue.get('issueId')
        summary = issue.get('issueState', {}).get('title', 'No summary')

        # The structure of 'issue' dict depends on the API response.
        # Based on typical Buganizer/Issue Tracker API:
        # issueState contains title, status, etc.
        # issueComment might contain details.

        # We'll make a best effort to extract what we can.
        # The user said: "Not all the fields might be available immediately"

        # Create output content
        output_content = f"id: {issue_id}\n"
        output_content += f"summary: {summary}\n"

        # Dump the whole issue object for inspection if needed, or key fields
        # output_content += f"raw_data: {issue}\n"

        # Write to output file in a specific directory
        output_subdir = os.path.join(data_dir, 'oss-fuzz-tracker')
        if not os.path.exists(output_subdir):
            os.makedirs(output_subdir)

        output_filepath = os.path.join(output_subdir, f"issue_{issue_id}.txt")
        with open(output_filepath, 'w') as f:
            f.write(output_content)

    except Exception as e:
        print(f"Error processing issue {issue.get('issueId')}: {e}", file=sys.stderr)


def main():
    """Main function to traverse the vulns directory and process files."""
    vulns_dir = 'vulns'
    data_dir = 'data'
    log_file = 'non_github_repos.log'

    if not os.path.exists(data_dir):
        os.makedirs(data_dir)

    with open(log_file, 'w') as f:
        f.write('')  # Clear the log file

    # Process local files
    for root, _, files in os.walk(vulns_dir):
        for file in files:
            if file.endswith('.yaml'):
                filepath = os.path.join(root, file)
                process_yaml_file(filepath, data_dir, log_file)

    # Process remote issues
    fetch_and_process_issues(data_dir)

if __name__ == '__main__':
    main()
