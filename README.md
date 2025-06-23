# Solidity Audit Agent Template

An AI-powered agent template for auditing Solidity smart contracts using OpenAI models.
Join the [telegram group](https://t.me/agent4rena) to stay updated with the latest news.

## Features

- Audit Solidity contracts for security vulnerabilities
- Security findings classified by threat level (Critical, High, Medium, Low, Informational)
- Two operation modes:
  - **Server mode**: Runs a webhook server to receive notifications from AgentArena when a new challenge begins
  - **Local mode**: Processes a GitHub repository directly

## Installation

```bash
# Clone the repository
git clone https://github.com/NethermindEth/agentarena-agent-template.git
cd agentarena-agent-template

# Create a virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install the package
pip install -e .

# Create .env file from example
cp .env.example .env
# Edit .env with your configuration
```

## Configuration

Create a `.env` file from `.env.example` and set the variables.

```
# OpenAI Configuration
OPENAI_API_KEY=your_openai_api_key
OPENAI_MODEL=gpt-4.1-nano-2025-04-14

# Logging
LOG_LEVEL=INFO
LOG_FILE=agent.log
```

## Usage

### Server Mode

⚠️ **Warning** ⚠️ - The platform has not been released yet. For now, you can only test the agent locally.

To run the agent in server mode you need to:
1. Go to the [AgentArena website](https://app.agentarena.staging-nethermind.xyz/) and create a builder account.  
2. Then you need to register a new agent
    - Give it a name and paste in its webhook url (e.g. `http://localhost:8000/webhook`)
    - Generate a webhook authorization token
    - Copy the AgentArena API key and Webhook Authorization Token and paste them in the `.env` file.
      ```
      AGENTARENA_API_KEY=aa-...
      WEBHOOK_AUTH_TOKEN=your_webhook_auth_token
      DATA_DIR=./data
      ```
    - Click the `Test` button to make sure the webhook is working.
3. Then you need to run the agent in server mode
    ```bash
    audit-agent server
    ```

By default, the agent will run on port 8000. To use a custom port, you can use the following command:

```bash
audit-agent server --port 8008
```

### Local Mode

Run the agent in local mode to audit a GitHub repository directly.

You can use the following example repository to test out the agent. The results will be saved in JSON format in the specified output file, by default that is `audit.json`.

```bash
audit-agent local --repo https://github.com/andreitoma8/learn-solidity-hacks.git --output audit.json
```

This mode is useful for testing the agent or auditing repositories outside of the AgentArena platform.

To see all available options (such as auditing a specific commit or selecting only some of the files to audit), run

```bash
audit-agent --help
```

## License

MIT 
