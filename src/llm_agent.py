"""
llm_agent.py - AI Brain of LIGHTUS

PURPOSE:
This file handles all communication with Claude AI via AWS Bedrock.
It takes user events, analyzes them, and returns threat assessment
with MITRE ATT&CK mapping.

HOW IT WORKS:
1. Receives batch of events from parser
2. Formats them into a prompt with MITRE + AWS context
3. Calls Claude via Bedrock
4. Parses and validates the response
5. Returns severity + MITRE techniques + reasoning
"""

import boto3
import json
import re
import logging

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class LLMAgent:
    """
    LLM Agent that uses Claude to analyze CloudTrail events
    and map them to MITRE ATT&CK techniques.
    
    Attributes:
        region (str): AWS region for Bedrock
        model_id (str): Claude model ID to use
        bedrock (boto3.client): Bedrock runtime client
    """
    
    def __init__(self, region='us-east-1', model_id='anthropic.claude-3-haiku-20240307-v1:0'):
        """
        Initialize the LLM Agent with Bedrock client.
        
        Args:
            region: AWS region where Bedrock is available (us-east-1)
            model_id: Claude model ID (Haiku is cheapest, fastest)
        
        Note:
            Claude Haiku costs ~$0.00025 per 1K tokens
            Perfect for our use case (short prompts, frequent calls)
        """
        self.region = region
        self.model_id = model_id
        self.bedrock = boto3.client('bedrock-runtime', region_name=region)
        logger.info(f"🤖 LLM Agent initialized with model: {model_id} in {region}")
    
    def analyze(self, events):
        """
        Analyze a batch of user events using Claude.
        
        Args:
            events: List of CloudTrail event dictionaries from same user
        
        Returns:
            Dictionary with:
                - severity: Low/Medium/High/Critical
                - mitre_techniques: List of MITRE technique IDs
                - reasoning: Human-readable explanation
                - confidence: 0.0-1.0 score
        
        How it works:
            1. Summarizes events (limit to 5 to save tokens)
            2. Builds prompt with MITRE context
            3. Calls Claude API
            4. Parses JSON response
            5. Returns structured result
        """
        if not events:
            logger.warning("⚠️ Empty events batch received")
            return {
                "severity": "Low", 
                "mitre_techniques": [], 
                "confidence": 0.0, 
                "reasoning": "No events to analyze"
            }
        
        logger.info(f"🔍 Analyzing batch of {len(events)} events")
        
        # Prepare events summary (limit to 5 to manage tokens and costs)
        summary = []
        for e in events[:5]:  # Only take first 5 events
            summary.append({
                "eventName": e.get('eventName', 'unknown'),
                "eventTime": e.get('eventTime', 'unknown'),
                "userArn": e.get('userIdentity', {}).get('arn', 'unknown'),
                "sourceIP": e.get('sourceIPAddress', 'unknown')
            })
        
        # Build the prompt with MITRE context
        prompt = self._build_prompt(summary)
        
        try:
            # Call Claude
            response = self._call_claude(prompt)
            
            # Parse and validate response
            result = self._parse_response(response)
            
            logger.info(f"✅ Analysis complete: {result['severity']}")
            if result['mitre_techniques']:
                logger.info(f"   MITRE: {', '.join(result['mitre_techniques'])}")
            
            return result
            
        except Exception as e:
            logger.error(f"❌ Error in Claude analysis: {e}")
            return {
                "severity": "Medium",
                "mitre_techniques": [],
                "confidence": 0.0,
                "reasoning": f"Analysis failed: {str(e)}"
            }
    
    def _build_prompt(self, events_summary):
        """
        Build the prompt with MITRE context and event data.
        
        This is the most important part - teaching Claude
        what to look for in AWS CloudTrail logs.
        """
        events_json = json.dumps(events_summary, indent=2)
        
        prompt = f"""You are LIGHTUS, an AWS insider threat detection expert. Your job is to analyze CloudTrail events and identify suspicious behavior.

UNDERSTANDING MITRE TECHNIQUES IN AWS CONTEXT:

🔐 T1078 - Valid Accounts (Credential Access)
What it looks like in AWS:
- User assumes a role they've never used before
- API calls from unusual geographic locations
- Console login without MFA followed by privilege escalation

👤 T1098 - Account Manipulation (Persistence)
What it looks like in AWS:
- CreateUser, CreateLoginProfile, CreateAccessKey
- AttachUserPolicy to non-admin accounts
- Adding users to privileged groups at odd hours

📂 T1005 - Data from Local System (Collection)
What it looks like in AWS:
- Multiple GetObject calls to S3 buckets (especially sensitive ones)
- BatchGetSecret from Secrets Manager
- Downloading many files in short time window

🛡️ T1562 - Impair Defenses (Defense Evasion)
What it looks like in AWS:
- StopLogging on CloudTrail
- DeleteTrail or UpdateTrail
- Disabling AWS Config or GuardDuty

Now analyze these CloudTrail events from the same user:

{events_json}

Return ONLY a valid JSON object with this exact structure:
{{
    "severity": "Low" or "Medium" or "High" or "Critical",
    "mitre_techniques": ["TXXXX", "TYYYY"],
    "confidence": 0.0 to 1.0,
    "reasoning": "Brief explanation of why this is suspicious or not"
}}

JSON Response:"""
        
        return prompt
    
    def _call_claude(self, prompt):
        """
        Make the actual API call to Bedrock Claude.
        """
        request_body = {
            "anthropic_version": "bedrock-2023-05-31",
            "max_tokens": 500,
            "messages": [
                {"role": "user", "content": prompt}
            ]
        }
        
        response = self.bedrock.invoke_model(
            modelId=self.model_id,
            body=json.dumps(request_body)
        )
        
        # Parse response
        response_body = json.loads(response['body'].read())
        return response_body['content'][0]['text']
    
    def _parse_response(self, text_response):
        """
        Extract and validate JSON from Claude's response.
        
        Claude sometimes adds extra text before/after JSON,
        so we need to extract just the JSON part.
        """
        try:
            # Find JSON between curly braces
            json_match = re.search(r'\{.*\}', text_response, re.DOTALL)
            
            if json_match:
                result = json.loads(json_match.group())
                
                # Validate required fields
                required = ['severity', 'mitre_techniques', 'confidence', 'reasoning']
                if all(field in result for field in required):
                    return result
                else:
                    logger.warning("⚠️ Missing fields in response")
                    return {
                        "severity": "Medium",
                        "mitre_techniques": [],
                        "confidence": 0.5,
                        "reasoning": "Incomplete response from Claude"
                    }
            else:
                logger.warning("⚠️ No JSON found in response")
                return {
                    "severity": "Medium",
                    "mitre_techniques": [],
                    "confidence": 0.5,
                    "reasoning": "No JSON in response"
                }
                
        except json.JSONDecodeError as e:
            logger.error(f"❌ Failed to parse JSON: {e}")
            return {
                "severity": "Medium",
                "mitre_techniques": [],
                "confidence": 0.0,
                "reasoning": f"JSON parse error"
            }
