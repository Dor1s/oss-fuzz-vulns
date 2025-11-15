import os
import yaml
import re

def process_yaml_file(filepath, data_dir, log_file):
    """Processes a single YAML file."""
    try:
        with open(filepath, 'r') as f:
            data = yaml.safe_load(f)
    except yaml.YAMLError as e:
        print(f"Error parsing YAML file: {filepath}\n{e}")
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
        print(f"Error processing file: {filepath}\n{e}")

def main():
    """Main function to traverse the vulns directory and process files."""
    vulns_dir = 'vulns'
    data_dir = 'data'
    log_file = 'non_github_repos.log'

    if not os.path.exists(data_dir):
        os.makedirs(data_dir)

    with open(log_file, 'w') as f:
        f.write('')  # Clear the log file

    for root, _, files in os.walk(vulns_dir):
        for file in files:
            if file.endswith('.yaml'):
                filepath = os.path.join(root, file)
                process_yaml_file(filepath, data_dir, log_file)

if __name__ == '__main__':
    main()
