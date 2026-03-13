// components/CybersecurityChatbot.jsx
'use client';

import { useState, useRef, useEffect } from 'react';
import axios from 'axios';
import ReactMarkdown from 'react-markdown';

export default function CybersecurityChatbot() {
  const [messages, setMessages] = useState([
    {
      role: 'assistant',
      content: 'Hello! I am your Cybersecurity AI Assistant. Ask me anything about cybersecurity, ethical hacking, network security, malware analysis, or security best practices.'
    }
  ]);
  const [input, setInput] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  const messagesEndRef = useRef(null);

  // API Configuration
  const API_KEY = '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';
  const API_URL = 'https://openrouter.ai/api/v1/chat/completions';

  // Model name for Nemotron
  const MODEL_NAME = 'nvidia/nemotron-3-nano-30b-a3b';

  // Cybersecurity-specific system prompt
  const systemPrompt = `You are a specialized Cybersecurity AI Assistant. Your expertise includes:
1. Network Security & Firewall configuration
2. Ethical Hacking & Penetration Testing
3. Malware Analysis & Reverse Engineering
4. Cryptography & Encryption methods
5. Security Compliance (GDPR, HIPAA, PCI-DSS)
6. Incident Response & Threat Hunting
7. Cloud Security (AWS, Azure, GCP)
8. IoT Security & Mobile Security
9. Security Best Practices & Hardening
10. Security Tools (Wireshark, Metasploit, Nmap, Burp Suite)

IMPORTANT RULES:
- Only answer cybersecurity-related questions
- If a question is unrelated to cybersecurity, politely decline and redirect to cybersecurity topics
- Provide accurate, up-to-date security information
- Never provide instructions for illegal activities
- Always emphasize ethical hacking principles
- Include practical examples and code snippets when relevant
- Format responses with clear sections using markdown`;

  const scrollToBottom = () => {
    messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  };

  useEffect(() => {
    scrollToBottom();
  }, [messages]);

  const handleSubmit = async (e) => {
    e.preventDefault();

    if (!input.trim() || loading) return;

    const userMessage = input.trim();

    // Check if the question is cybersecurity-related

    const cybersecurityKeywords = [
      // General Security Terms
      'security', 'cyber', 'cybersecurity', 'infosec', 'information security', 'netsec', 'network security',
      'appsec', 'application security', 'devsecops', 'secops', 'security operations',

      // Threats & Attacks
      'hack', 'hacker', 'hacking', 'cracker', 'attack', 'threat', 'threat actor', 'apt', 'advanced persistent threat',
      'malware', 'virus', 'worm', 'trojan', 'rootkit', 'backdoor', 'botnet', 'ransomware', 'spyware',
      'adware', 'keylogger', 'rat', 'remote access trojan', 'cryptojacker', 'cryptominer', 'fileless malware',
      'polymorphic', 'metamorphic', 'logic bomb', 'time bomb', 'exploit kit',

      // Attack Types
      'phishing', 'spear phishing', 'whaling', 'vishing', 'smishing', 'pharming', 'pretexting',
      'social engineering', 'baiting', 'quid pro quo', 'tailgating', 'piggybacking',
      'ddos', 'dos', 'distributed denial of service', 'syn flood', 'udp flood', 'ping flood',
      'amplification attack', 'reflection attack', 'slowloris', 'http flood',
      'mitm', 'man in the middle', 'arp spoofing', 'dns spoofing', 'session hijacking',
      'replay attack', 'evil twin', 'rogue access point',
      'brute force', 'dictionary attack', 'rainbow table', 'credential stuffing', 'password spraying',
      'sql injection', 'sqli', 'nosql injection', 'blind sql injection',
      'xss', 'cross site scripting', 'stored xss', 'reflected xss', 'dom xss',
      'csrf', 'cross site request forgery', 'ssrf', 'server side request forgery',
      'rce', 'remote code execution', 'code injection', 'command injection', 'xml injection',
      'ldap injection', 'xpath injection', 'template injection', 'ssti',
      'lfi', 'local file inclusion', 'rfi', 'remote file inclusion', 'directory traversal', 'path traversal',
      'privilege escalation', 'lateral movement', 'pivoting', 'tunneling',
      'buffer overflow', 'stack overflow', 'heap overflow', 'integer overflow',
      'format string', 'use after free', 'race condition', 'toctou',
      'clickjacking', 'ui redressing', 'frame injection',
      'typosquatting', 'domain squatting', 'subdomain takeover',
      'watering hole', 'drive by download', 'supply chain attack',

      // Vulnerabilities
      'vulnerability', 'vuln', 'exploit', 'zero-day', '0-day', 'n-day', 'one-day',
      'cve', 'common vulnerabilities and exposures', 'cvss', 'cwe', 'common weakness enumeration',
      'bug bounty', 'responsible disclosure', 'coordinated disclosure',
      'misconfiguration', 'weak configuration', 'default credentials', 'hardcoded credentials',
      'insecure deserialization', 'xxe', 'xml external entity',
      'broken authentication', 'broken access control', 'security misconfiguration',
      'sensitive data exposure', 'insufficient logging', 'insecure communication',

      // Defense & Protection
      'patch', 'patching', 'update', 'hotfix', 'security patch', 'vulnerability management',
      'firewall', 'waf', 'web application firewall', 'ngfw', 'next generation firewall',
      'ids', 'intrusion detection system', 'ips', 'intrusion prevention system',
      'nids', 'hids', 'network intrusion detection', 'host intrusion detection',
      'antivirus', 'anti-malware', 'endpoint protection', 'edr', 'endpoint detection response',
      'xdr', 'extended detection response', 'mdr', 'managed detection response',
      'dlp', 'data loss prevention', 'data leakage prevention',
      'siem', 'security information event management', 'soar', 'security orchestration automation',
      'soc', 'security operations center', 'noc', 'network operations center',
      'sandbox', 'sandboxing', 'isolation', 'containerization', 'micro-segmentation',
      'honeypot', 'honeynet', 'deception technology', 'canary tokens',

      // Encryption & Cryptography
      'encryption', 'cryptography', 'crypto', 'cipher', 'decrypt', 'decryption',
      'aes', 'rsa', 'des', '3des', 'blowfish', 'twofish', 'ecc', 'elliptic curve',
      'symmetric encryption', 'asymmetric encryption', 'public key', 'private key',
      'hash', 'hashing', 'md5', 'sha1', 'sha256', 'sha512', 'bcrypt', 'scrypt', 'argon2',
      'salt', 'salting', 'pepper', 'hmac', 'mac', 'message authentication code',
      'digital signature', 'certificate', 'pki', 'public key infrastructure',
      'ssl', 'tls', 'https', 'certificate authority', 'ca', 'x509',
      'perfect forward secrecy', 'pfs', 'diffie-hellman', 'key exchange',
      'vpn', 'virtual private network', 'ipsec', 'wireguard', 'openvpn',
      'end to end encryption', 'e2ee', 'pgp', 'gpg', 'gnupg',
      'quantum cryptography', 'post-quantum', 'homomorphic encryption',

      // Authentication & Access Control
      'authentication', 'authorization', 'access control', 'identity management', 'iam',
      'password', 'passphrase', 'pin', 'password policy', 'password complexity',
      'mfa', 'multi-factor authentication', '2fa', 'two-factor authentication',
      'otp', 'one time password', 'totp', 'hotp',
      'biometric', 'fingerprint', 'facial recognition', 'retina scan', 'iris scan',
      'sso', 'single sign on', 'saml', 'oauth', 'openid', 'oidc', 'jwt', 'json web token',
      'ldap', 'active directory', 'kerberos', 'ntlm', 'radius', 'tacacs',
      'rbac', 'role based access control', 'abac', 'attribute based access control',
      'mac', 'mandatory access control', 'dac', 'discretionary access control',
      'least privilege', 'principle of least privilege', 'separation of duties', 'need to know',
      'privileged access management', 'pam', 'session management', 'token',

      // Network Security
      'network security', 'network segmentation', 'vlan', 'dmz', 'demilitarized zone',
      'proxy', 'forward proxy', 'reverse proxy', 'socks proxy', 'http proxy',
      'load balancer', 'nat', 'network address translation', 'port forwarding',
      'packet filtering', 'stateful inspection', 'deep packet inspection', 'dpi',
      'sniffing', 'packet capture', 'pcap', 'network monitoring', 'traffic analysis',
      'bandwidth', 'throughput', 'latency', 'jitter', 'packet loss',
      'tcp', 'udp', 'icmp', 'arp', 'dns', 'dhcp', 'snmp',
      'port scanning', 'service enumeration', 'os fingerprinting', 'banner grabbing',

      // Pentesting & Red Team
      'pentest', 'penetration testing', 'ethical hacking', 'white hat', 'black hat', 'grey hat',
      'red team', 'blue team', 'purple team', 'adversary simulation',
      'reconnaissance', 'recon', 'osint', 'open source intelligence', 'footprinting',
      'enumeration', 'scanning', 'vulnerability scanning', 'exploitation', 'post-exploitation',
      'persistence', 'covering tracks', 'privilege escalation', 'credential dumping',
      'nmap', 'metasploit', 'burp suite', 'burp', 'wireshark', 'tcpdump',
      'nessus', 'nikto', 'sqlmap', 'john', 'john the ripper', 'hashcat', 'hydra',
      'aircrack', 'kismet', 'snort', 'suricata', 'zeek', 'bro',
      'kali linux', 'parrot os', 'backtrack', 'pentesting framework',
      'mitre attack', 'att&ck', 'mitre framework', 'kill chain', 'cyber kill chain',
      'ttp', 'tactics techniques procedures', 'ioc', 'indicator of compromise',

      // Web Security
      'web security', 'owasp', 'owasp top 10', 'cors', 'csp', 'content security policy',
      'same origin policy', 'sop', 'http security headers', 'hsts', 'x-frame-options',
      'cookies', 'session cookies', 'httponly', 'secure flag', 'samesite',
      'api security', 'rest api', 'graphql', 'soap', 'xml-rpc',
      'rate limiting', 'throttling', 'captcha', 'recaptcha', 'bot detection',
      'input validation', 'output encoding', 'sanitization', 'escaping',
      'parameterized queries', 'prepared statements', 'stored procedures',
      'authentication bypass', 'authorization bypass', 'broken object level authorization',

      // Mobile Security
      'mobile security', 'android security', 'ios security', 'mobile app security',
      'apk', 'ipa', 'decompile', 'reverse engineering', 'obfuscation',
      'jailbreak', 'root', 'rooting', 'sideloading',
      'certificate pinning', 'ssl pinning', 'mobile malware',

      // Cloud Security
      'cloud security', 'aws security', 'azure security', 'gcp security',
      'cloud access security broker', 'casb', 'cloud posture management', 'cspm',
      'container security', 'docker security', 'kubernetes security', 'k8s security',
      'serverless security', 'lambda security', 'function security',
      's3 bucket', 'blob storage', 'object storage', 'misconfigured bucket',
      'cloud iam', 'service account', 'managed identity',

      // Compliance & Frameworks
      'compliance', 'regulatory compliance', 'audit', 'auditing',
      'gdpr', 'general data protection regulation', 'ccpa', 'california consumer privacy act',
      'pci dss', 'pci', 'payment card industry', 'hipaa', 'health insurance portability',
      'sox', 'sarbanes oxley', 'glba', 'gramm leach bliley',
      'fisma', 'federal information security', 'fedramp', 'federal risk authorization',
      'iso 27001', 'iso27001', 'iso 27002', 'nist', 'nist framework',
      'cis controls', 'cis benchmarks', 'cobit', 'itil', 'cmmc',
      'risk assessment', 'risk management', 'risk analysis', 'threat modeling',
      'business continuity', 'disaster recovery', 'bcp', 'drp', 'incident response',

      // Forensics & Incident Response
      'digital forensics', 'computer forensics', 'incident response', 'ir',
      'incident handling', 'incident management', 'breach response',
      'forensic analysis', 'memory forensics', 'disk forensics', 'network forensics',
      'evidence collection', 'chain of custody', 'write blocker', 'forensic imaging',
      'malware analysis', 'static analysis', 'dynamic analysis', 'behavioral analysis',
      'reverse engineering', 'disassembly', 'decompilation', 'debugging',
      'log analysis', 'log aggregation', 'log correlation', 'timeline analysis',
      'threat hunting', 'threat intelligence', 'cyber threat intelligence', 'cti',
      'attribution', 'threat actor profiling', 'campaign tracking',

      // Governance & Policy
      'security policy', 'security governance', 'security architecture',
      'security awareness', 'security training', 'phishing simulation',
      'acceptable use policy', 'aup', 'data classification', 'data governance',
      'privacy', 'data privacy', 'data protection', 'personally identifiable information', 'pii',
      'protected health information', 'phi', 'payment card data', 'sensitive data',
      'data retention', 'data disposal', 'secure deletion', 'data sanitization',
      'third party risk', 'vendor risk', 'supply chain risk', 'vendor assessment',

      // Emerging Technologies
      'ai security', 'machine learning security', 'adversarial ml', 'model poisoning',
      'iot security', 'internet of things', 'embedded security', 'firmware security',
      'scada', 'ics', 'industrial control systems', 'operational technology', 'ot security',
      'blockchain security', 'smart contract security', 'cryptocurrency security',
      '5g security', 'edge computing security', 'quantum computing',

      // Miscellaneous
      'security breach', 'data breach', 'breach notification', 'breach response',
      'security incident', 'security event', 'false positive', 'false negative',
      'security metrics', 'kpi', 'key performance indicator', 'security posture',
      'attack surface', 'threat surface', 'exposure', 'hardening', 'system hardening',
      'baseline', 'security baseline', 'secure configuration', 'secure by design',
      'defense in depth', 'layered security', 'security controls', 'compensating controls',
      'vulnerability disclosure', 'bug report', 'security advisory', 'security bulletin',
      'security researcher', 'white paper', 'proof of concept', 'poc', 'demo',
      'ctf', 'capture the flag', 'wargames', 'hacking competition',
      'darknet', 'dark web', 'deep web', 'tor', 'onion routing', 'anonymity'
    ];
    const isCybersecurityQuestion = cybersecurityKeywords.some(keyword =>
      userMessage.toLowerCase().includes(keyword)
    );

    if (!isCybersecurityQuestion) {
      setMessages(prev => [...prev, {
        role: 'user',
        content: userMessage
      }, {
        role: 'assistant',
        content: 'I specialize only in cybersecurity topics. Please ask me about network security, ethical hacking, malware analysis, encryption, security compliance, or related cybersecurity subjects.'
      }]);
      setInput('');
      return;
    }

    // Add user message
    const updatedMessages = [...messages, { role: 'user', content: userMessage }];
    setMessages(updatedMessages);
    setInput('');
    setLoading(true);
    setError(null);

    try {
      const response = await axios.post(
        API_URL,
        {
          model: MODEL_NAME,
          messages: [
            { role: 'system', content: systemPrompt },
            ...updatedMessages
          ],
          max_tokens: 1000,
          temperature: 0.7,
        },
        {
          headers: {
            'Authorization': `Bearer ${API_KEY}`,
            'Content-Type': 'application/json',
          }
        }
      );

      const aiResponse = response.data.choices[0].message.content;

      setMessages(prev => [...prev, {
        role: 'assistant',
        content: aiResponse
      }]);

    } catch (err) {
      console.error('Error:', err);
      setError('Failed to get response. Please try again.');

      setMessages(prev => [...prev, {
        role: 'assistant',
        content: 'Sorry, I encountered an error. Please try your question again.'
      }]);
    } finally {
      setLoading(false);
    }
  };

  const clearChat = () => {
    setMessages([
      {
        role: 'assistant',
        content: 'Hello! I am your Cybersecurity AI Assistant. Ask me anything about cybersecurity.'
      }
    ]);
    setError(null);
  };

  return (
    <div className="flex flex-col h-[800px] w-full max-w-4xl mx-auto bg-gray-900 text-white rounded-xl shadow-2xl overflow-hidden">
      {/* Header */}
      <div className="bg-gradient-to-r from-blue-900 to-purple-900 p-4">
        <div className="flex justify-between items-center">
          <div className="flex items-center space-x-3">
            <div className="w-10 h-10 bg-gradient-to-r from-cyan-500 to-blue-500 rounded-full flex items-center justify-center">

            </div>
            <div>
              <h2 className="text-xl font-bold">Cybersecurity AI Assistant</h2>
              <p className="text-sm text-blue-200">Specialized in security topics only</p>
            </div>
          </div>
          <button
            onClick={clearChat}
            className="px-4 py-2 bg-red-600 hover:bg-red-700 rounded-lg text-sm font-medium transition"
          >
            Clear Chat
          </button>
        </div>
      </div>

      {/* Chat Messages */}
      <div className="flex-1 overflow-y-auto p-4 space-y-4">
        {messages.map((message, index) => (
          <div
            key={index}
            className={`flex ${message.role === 'user' ? 'justify-end' : 'justify-start'}`}
          >
            <div
              className={`max-w-[80%] rounded-2xl p-4 ${message.role === 'user'
                ? 'bg-gradient-to-r from-blue-700 to-indigo-700'
                : 'bg-gradient-to-r from-gray-800 to-gray-700'
                }`}
            >
              <div className="flex items-center space-x-2 mb-2">
                <span className="font-bold">
                  {message.role === 'user' ? ' You' : ' Cyber Assistant'}
                </span>
              </div>
              <div className="prose prose-invert max-w-none">
                <ReactMarkdown>{message.content}</ReactMarkdown>
              </div>
            </div>
          </div>
        ))}

        {loading && (
          <div className="flex justify-start">
            <div className="bg-gradient-to-r from-gray-800 to-gray-700 rounded-2xl p-4">
              <div className="flex space-x-2">
                <div className="w-2 h-2 bg-cyan-500 rounded-full animate-pulse"></div>
                <div className="w-2 h-2 bg-cyan-500 rounded-full animate-pulse delay-150"></div>
                <div className="w-2 h-2 bg-cyan-500 rounded-full animate-pulse delay-300"></div>
              </div>
            </div>
          </div>
        )}

        <div ref={messagesEndRef} />
      </div>

      {/* Error Display */}
      {error && (
        <div className="mx-4 p-3 bg-red-900/50 border border-red-700 rounded-lg">
          <p className="text-sm text-red-200">{error}</p>
        </div>
      )}

      {/* Input Form */}
      <form onSubmit={handleSubmit} className="p-4 border-t border-gray-700 bg-gray-800">
        <div className="flex space-x-3">
          <input
            type="text"
            value={input}
            onChange={(e) => setInput(e.target.value)}
            placeholder="Ask about cybersecurity (network security, hacking, encryption, etc.)"
            className="flex-1 p-3 bg-gray-700 border border-gray-600 rounded-lg focus:outline-none focus:ring-2 focus:ring-cyan-500"
            disabled={loading}
          />
          <button
            type="submit"
            disabled={loading}
            className="px-6 py-3 bg-gradient-to-r from-cyan-600 to-blue-600 hover:from-cyan-700 hover:to-blue-700 rounded-lg font-medium disabled:opacity-50 transition"
          >
            {loading ? 'Analyzing...' : 'Send'}
          </button>
        </div>

        {/* Quick Cybersecurity Topics */}
        <div className="mt-3 flex flex-wrap gap-2">
          <span className="text-xs text-gray-400 mr-2">Try:</span>
          {[
            'Explain SQL injection',
            'Best password practices',
          ].map((topic, index) => (
            <button
              key={index}
              type="button"
              onClick={() => setInput(topic)}
              className="text-xs px-3 py-1 bg-gray-700 hover:bg-gray-600 rounded-full transition"
            >
              {topic}
            </button>
          ))}
        </div>
      </form>
    </div>
  );
}
