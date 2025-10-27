"""
Smart Browser-Based Vulnerability Tester
Uses Browser Use AI agent for intelligent browser automation and testing
"""

import base64
import asyncio
from typing import Dict, List, Optional
from urllib.parse import urljoin, urlparse, parse_qs, urlencode, urlunparse
from utils.logger import get_logger

logger = get_logger(__name__)


class SmartBrowserTester:
    """AI-powered browser-based vulnerability testing with Browser Use."""
    
    def __init__(self, config: Dict):
        """Initialize smart browser tester with Browser Use."""
        self.config = config
        self.advanced_config = config.get('advanced', {})
        self.screenshot_enabled = self.advanced_config.get('screenshot_enabled', False)
        self.screenshots = []
        self.browser = None
        self.agent = None
        self.use_browser_use = False
        
    async def initialize_browser(self):
        """Initialize Browser Use agent or fallback to Playwright."""
        try:
            # Try to use Browser Use first (more powerful AI agent)
            from browser_use import Agent
            from langchain_openai import ChatOpenAI
            
            # Get AI configuration
            ai_config = self.config.get('ai_providers', {}).get('openai', {})
            api_key = ai_config.get('api_key', '')
            model = ai_config.get('model', 'gpt-4o')
            
            if api_key and api_key.startswith('sk-'):
                # Initialize Browser Use with AI
                llm = ChatOpenAI(
                    model_name=model,
                    openai_api_key=api_key,
                    temperature=0.3  # Lower temperature for more deterministic security testing
                )
                
                # Initialize Agent without task (will be set per test)
                self.agent = Agent(
                    task="Navigate to homepage",  # Dummy initial task
                    llm=llm
                )
                
                self.use_browser_use = True
                logger.info("Browser Use AI agent initialized successfully")
                return True
            else:
                logger.info("OpenAI API key not configured, falling back to Playwright")
                return await self._initialize_playwright()
                
        except ImportError as e:
            logger.info("Browser Use not installed, falling back to Playwright")
            logger.info("Install with: pip install browser-use langchain-openai")
            return await self._initialize_playwright()
        except Exception as e:
            logger.warning(f"Failed to initialize Browser Use: {e}, falling back to Playwright")
            logger.debug(f"Browser Use error details: {str(e)}")
            return await self._initialize_playwright()
    
    async def _initialize_playwright(self):
        """Fallback: Initialize standard Playwright browser."""
        try:
            from playwright.async_api import async_playwright
            
            self.playwright = await async_playwright().start()
            self.browser = await self.playwright.chromium.launch(
                headless=True,
                args=['--no-sandbox', '--disable-setuid-sandbox']
            )
            self.context = await self.browser.new_context(
                viewport={'width': 1920, 'height': 1080},
                user_agent='Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
            )
            self.page = await self.context.new_page()
            self.use_browser_use = False
            logger.info("Playwright browser initialized successfully")
            return True
        except ImportError:
            logger.warning("Playwright not installed. Install with: pip install playwright && playwright install chromium")
            return False
        except Exception as e:
            logger.error(f"Failed to initialize browser: {e}")
            return False
    
    async def close_browser(self):
        """Close browser and cleanup."""
        try:
            if self.use_browser_use and self.agent:
                # Browser Use handles cleanup automatically
                self.agent = None
                logger.info("Browser Use agent cleaned up")
            else:
                # Playwright cleanup
                if hasattr(self, 'page') and self.page:
                    await self.page.close()
                if hasattr(self, 'context') and self.context:
                    await self.context.close()
                if hasattr(self, 'browser') and self.browser:
                    await self.browser.close()
                if hasattr(self, 'playwright') and self.playwright:
                    await self.playwright.stop()
                logger.info("Playwright browser closed successfully")
        except Exception as e:
            logger.error(f"Error closing browser: {e}")
    
    async def take_screenshot(self, title: str = "screenshot", page=None) -> Optional[str]:
        """Take screenshot and return base64 encoded data URL."""
        if not self.screenshot_enabled:
            return None
        
        try:
            # Use provided page or default
            screenshot_page = page or self.page
            if not screenshot_page:
                return None
            
            screenshot_bytes = await screenshot_page.screenshot(full_page=False)
            base64_screenshot = base64.b64encode(screenshot_bytes).decode('utf-8')
            data_url = f"data:image/png;base64,{base64_screenshot}"
            
            self.screenshots.append({
                'title': title,
                'data_url': data_url
            })
            
            logger.debug(f"Screenshot captured: {title}")
            return data_url
        except Exception as e:
            logger.error(f"Failed to take screenshot: {e}")
            return None
    
    async def test_xss_browser(self, url: str, payloads: List[str]) -> List[Dict]:
        """Test XSS vulnerabilities using AI-powered browser automation."""
        vulnerabilities = []
        
        if not self.agent and not self.page:
            if not await self.initialize_browser():
                return vulnerabilities
        
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        
        if not params:
            return vulnerabilities
        
        logger.info(f"Testing XSS with {'Browser Use AI' if self.use_browser_use else 'browser'} on: {url}")
        
        # If using Browser Use AI agent, use intelligent approach
        if self.use_browser_use and self.agent:
            return await self._test_xss_with_browser_use(url, payloads, params)
        
        # Otherwise use standard Playwright approach
        return await self._test_xss_with_playwright(url, payloads, params)
    
    async def _test_xss_with_browser_use(self, url: str, payloads: List[str], params: Dict) -> List[Dict]:
        """Test XSS using Browser Use AI agent."""
        vulnerabilities = []
        
        for param_name in list(params.keys())[:3]:  # Test first 3 parameters
            for payload in payloads[:2]:  # Test first 2 payloads per param
                try:
                    # Create AI task for XSS testing
                    task = f"""
                    Navigate to {url} and test for XSS vulnerability:
                    1. Find the input field or parameter named '{param_name}'
                    2. Insert the payload: {payload}
                    3. Submit the form or trigger the action
                    4. Check if an alert dialog appears or if the payload is reflected in the page
                    5. Report if XSS is detected
                    """
                    
                    # Create new agent with task (Browser Use API requirement)
                    from browser_use import Agent
                    from langchain_openai import ChatOpenAI
                    
                    ai_config = self.config.get('ai_providers', {}).get('openai', {})
                    llm = ChatOpenAI(
                        model_name=ai_config.get('model', 'gpt-4o'),
                        openai_api_key=ai_config.get('api_key', ''),
                        temperature=0.3
                    )
                    
                    agent = Agent(task=task, llm=llm)
                    result = await agent.run()
                    
                    # Get the browser page for screenshot
                    screenshot_url = None
                    if hasattr(agent, 'browser') and hasattr(agent.browser, 'page'):
                        screenshot_url = await self.take_screenshot(f"XSS_AI_{param_name}", agent.browser.page)
                    
                    # Analyze result - if AI found XSS
                    result_text = str(result).lower()
                    if any(indicator in result_text for indicator in ['alert', 'xss detected', 'vulnerability found', 'payload executed']):
                        vulnerabilities.append({
                            'type': 'Cross-Site Scripting (XSS) - AI Verified',
                            'severity': 'high',
                            'url': url,
                            'parameter': param_name,
                            'payload': payload,
                            'evidence': f'Browser Use AI detected XSS execution: {result_text[:200]}',
                            'description': 'XSS vulnerability confirmed via AI-powered browser agent',
                            'remediation': 'Implement proper input validation and output encoding',
                            'screenshot': screenshot_url
                        })
                        logger.info(f"AI detected XSS on {url} - param: {param_name}")
                        break
                    
                except Exception as e:
                    logger.debug(f"Error in Browser Use XSS test: {e}")
                    continue
        
        return vulnerabilities
    
    async def _test_xss_with_playwright(self, url: str, payloads: List[str], params: Dict) -> List[Dict]:
        """Test XSS using standard Playwright."""
        vulnerabilities = []
        
        for param_name in params.keys():
            for payload in payloads[:3]:  # Test first 3 payloads
                try:
                    # Build test URL
                    test_params = params.copy()
                    test_params[param_name] = [payload]
                    test_query = urlencode(test_params, doseq=True)
                    test_url = urlunparse((
                        parsed.scheme,
                        parsed.netloc,
                        parsed.path,
                        parsed.params,
                        test_query,
                        parsed.fragment
                    ))
                    
                    # Navigate to URL
                    response = await self.page.goto(test_url, wait_until='networkidle', timeout=15000)
                    
                    # Check for XSS execution via console logs
                    console_messages = []
                    self.page.on('console', lambda msg: console_messages.append(msg.text))
                    
                    # Wait a bit for any scripts to execute
                    await asyncio.sleep(1)
                    
                    # Check if alert dialog appeared
                    dialog_detected = False
                    async def handle_dialog(dialog):
                        nonlocal dialog_detected
                        dialog_detected = True
                        await dialog.dismiss()
                    
                    self.page.on('dialog', handle_dialog)
                    
                    # Check page content for payload
                    page_content = await self.page.content()
                    
                    if payload in page_content or dialog_detected:
                        screenshot_url = await self.take_screenshot(f"XSS_{param_name}")
                        
                        vulnerabilities.append({
                            'type': 'Cross-Site Scripting (XSS) - Browser Verified',
                            'severity': 'high',
                            'url': url,
                            'parameter': param_name,
                            'payload': payload,
                            'evidence': f'XSS payload executed in browser. Dialog detected: {dialog_detected}',
                            'description': 'XSS vulnerability confirmed via browser execution',
                            'remediation': 'Implement proper input validation and output encoding',
                            'screenshot': screenshot_url
                        })
                        logger.info(f"XSS confirmed on {url} - param: {param_name}")
                        break
                    
                except Exception as e:
                    logger.debug(f"Error testing XSS with browser on {url}: {e}")
                    continue
        
        return vulnerabilities
    
    async def test_sqli_browser(self, url: str, payloads: List[str]) -> List[Dict]:
        """Test SQL injection using AI-powered browser automation."""
        vulnerabilities = []
        
        if not self.agent and not self.page:
            if not await self.initialize_browser():
                return vulnerabilities
        
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        
        if not params:
            return vulnerabilities
        
        logger.info(f"Testing SQLi with {'Browser Use AI' if self.use_browser_use else 'browser'} on: {url}")
        
        # If using Browser Use AI, use intelligent approach
        if self.use_browser_use and self.agent:
            return await self._test_sqli_with_browser_use(url, payloads, params, parsed)
        
        # Otherwise use standard Playwright
        return await self._test_sqli_with_playwright(url, payloads, params, parsed)
    
    async def _test_sqli_with_browser_use(self, url: str, payloads: List[str], params: Dict, parsed) -> List[Dict]:
        """Test SQLi using Browser Use AI agent."""
        vulnerabilities = []
        
        for param_name in list(params.keys())[:3]:
            for payload in payloads[:2]:
                try:
                    task = f"""
                    Navigate to {url} and test for SQL injection:
                    1. Find the input/parameter named '{param_name}'
                    2. Input the SQL payload: {payload}
                    3. Submit and analyze the response
                    4. Look for SQL error messages like: MySQL error, SQL syntax, database error, pg_query error
                    5. Report if SQL injection vulnerability is detected
                    """
                    
                    # Create new agent with task
                    from browser_use import Agent
                    from langchain_openai import ChatOpenAI
                    
                    ai_config = self.config.get('ai_providers', {}).get('openai', {})
                    llm = ChatOpenAI(
                        model_name=ai_config.get('model', 'gpt-4o'),
                        openai_api_key=ai_config.get('api_key', ''),
                        temperature=0.3
                    )
                    
                    agent = Agent(task=task, llm=llm)
                    result = await agent.run()
                    
                    # Get screenshot
                    screenshot_url = None
                    if hasattr(agent, 'browser') and hasattr(agent.browser, 'page'):
                        screenshot_url = await self.take_screenshot(f"SQLi_AI_{param_name}", agent.browser.page)
                    
                    # Check if AI found SQLi
                    result_text = str(result).lower()
                    if any(indicator in result_text for indicator in ['sql error', 'mysql', 'database error', 'syntax error', 'sql injection found']):
                        vulnerabilities.append({
                            'type': 'SQL Injection - AI Verified',
                            'severity': 'critical',
                            'url': url,
                            'parameter': param_name,
                            'payload': payload,
                            'evidence': f'Browser Use AI detected SQL error: {result_text[:200]}',
                            'description': 'SQL injection confirmed via AI-powered browser testing',
                            'remediation': 'Use parameterized queries or prepared statements',
                            'screenshot': screenshot_url
                        })
                        logger.info(f"AI detected SQLi on {url} - param: {param_name}")
                        break
                
                except Exception as e:
                    logger.debug(f"Error in Browser Use SQLi test: {e}")
                    continue
        
        return vulnerabilities
    
    async def _test_sqli_with_playwright(self, url: str, payloads: List[str], params: Dict, parsed) -> List[Dict]:
        """Test SQLi using standard Playwright."""
        vulnerabilities = []
        
        # SQL error patterns to look for
        sql_errors = [
            'SQL syntax',
            'mysql_fetch',
            'PostgreSQL.*ERROR',
            'Warning.*mysql',
            'valid MySQL result',
            'MySQLSyntaxErrorException',
            'SqlException',
            'SQLite/JDBCDriver',
            'Oracle error',
            'ODBC SQL Server Driver'
        ]
        
        for param_name in params.keys():
            for payload in payloads[:3]:
                try:
                    test_params = params.copy()
                    test_params[param_name] = [payload]
                    test_query = urlencode(test_params, doseq=True)
                    test_url = urlunparse((
                        parsed.scheme,
                        parsed.netloc,
                        parsed.path,
                        parsed.params,
                        test_query,
                        parsed.fragment
                    ))
                    
                    # Navigate and wait for response
                    await self.page.goto(test_url, wait_until='networkidle', timeout=15000)
                    page_content = await self.page.content()
                    
                    # Check for SQL errors in page
                    for error_pattern in sql_errors:
                        if error_pattern.lower() in page_content.lower():
                            screenshot_url = await self.take_screenshot(f"SQLi_{param_name}")
                            
                            vulnerabilities.append({
                                'type': 'SQL Injection - Browser Verified',
                                'severity': 'critical',
                                'url': url,
                                'parameter': param_name,
                                'payload': payload,
                                'evidence': f'SQL error detected in browser: {error_pattern}',
                                'description': 'SQL injection confirmed via browser-based testing',
                                'remediation': 'Use parameterized queries or prepared statements',
                                'screenshot': screenshot_url
                            })
                            logger.info(f"SQLi confirmed on {url} - param: {param_name}")
                            break
                    
                except Exception as e:
                    logger.debug(f"Error testing SQLi with browser on {url}: {e}")
                    continue
        
        return vulnerabilities
    
    async def test_dom_xss(self, url: str) -> List[Dict]:
        """Test for DOM-based XSS vulnerabilities."""
        vulnerabilities = []
        
        if not self.page:
            if not await self.initialize_browser():
                return vulnerabilities
        
        logger.info(f"Testing DOM XSS on: {url}")
        
        try:
            # Navigate to page
            await self.page.goto(url, wait_until='networkidle', timeout=15000)
            
            # Inject test payloads via hash/URL
            dom_payloads = [
                '#<img src=x onerror=alert(1)>',
                '#javascript:alert(1)',
                '#<svg/onload=alert(1)>'
            ]
            
            for payload in dom_payloads:
                try:
                    test_url = url + payload
                    await self.page.goto(test_url, wait_until='networkidle', timeout=10000)
                    
                    # Check for dialog
                    dialog_detected = False
                    async def handle_dialog(dialog):
                        nonlocal dialog_detected
                        dialog_detected = True
                        await dialog.dismiss()
                    
                    self.page.on('dialog', handle_dialog)
                    await asyncio.sleep(1)
                    
                    if dialog_detected:
                        screenshot_url = await self.take_screenshot("DOM_XSS")
                        
                        vulnerabilities.append({
                            'type': 'DOM-Based XSS',
                            'severity': 'high',
                            'url': url,
                            'payload': payload,
                            'evidence': 'Alert dialog triggered via DOM manipulation',
                            'description': 'DOM-based XSS vulnerability allows client-side code execution',
                            'remediation': 'Sanitize DOM operations and validate URL fragments',
                            'screenshot': screenshot_url
                        })
                        logger.info(f"DOM XSS confirmed on {url}")
                        break
                
                except Exception as e:
                    logger.debug(f"Error testing DOM XSS payload: {e}")
                    continue
        
        except Exception as e:
            logger.error(f"Error testing DOM XSS on {url}: {e}")
        
        return vulnerabilities
    
    async def test_clickjacking(self, url: str) -> List[Dict]:
        """Test for clickjacking vulnerabilities."""
        vulnerabilities = []
        
        if not self.page:
            if not await self.initialize_browser():
                return vulnerabilities
        
        logger.info(f"Testing clickjacking on: {url}")
        
        try:
            # Try to frame the page
            frame_html = f'''
            <!DOCTYPE html>
            <html>
            <head><title>Clickjacking Test</title></head>
            <body>
                <iframe src="{url}" width="100%" height="600px"></iframe>
            </body>
            </html>
            '''
            
            await self.page.set_content(frame_html)
            await asyncio.sleep(2)
            
            # Check if iframe loaded successfully
            frames = self.page.frames
            if len(frames) > 1:  # Main frame + iframe
                screenshot_url = await self.take_screenshot("Clickjacking")
                
                vulnerabilities.append({
                    'type': 'Clickjacking',
                    'severity': 'medium',
                    'url': url,
                    'evidence': 'Page can be embedded in iframe without X-Frame-Options protection',
                    'description': 'Site is vulnerable to clickjacking attacks',
                    'remediation': 'Implement X-Frame-Options or CSP frame-ancestors directive',
                    'screenshot': screenshot_url
                })
                logger.info(f"Clickjacking vulnerability confirmed on {url}")
        
        except Exception as e:
            logger.debug(f"Error testing clickjacking on {url}: {e}")
        
        return vulnerabilities
    
    async def test_hidden_elements(self, url: str, payloads: Dict[str, List[str]]) -> List[Dict]:
        """Test hidden elements for vulnerabilities using AI."""
        vulnerabilities = []
        
        if not self.agent and not self.page:
            if not await self.initialize_browser():
                return vulnerabilities
        
        logger.info(f"Testing hidden elements with {'Browser Use AI' if self.use_browser_use else 'browser'} on: {url}")
        
        if self.use_browser_use and self.agent:
            return await self._test_hidden_elements_with_browser_use(url, payloads)
        else:
            return await self._test_hidden_elements_with_playwright(url, payloads)
    
    async def _test_hidden_elements_with_browser_use(self, url: str, payloads: Dict[str, List[str]]) -> List[Dict]:
        """Use Browser Use AI to find and test hidden elements."""
        vulnerabilities = []
        
        try:
            from browser_use import Agent
            from langchain_openai import ChatOpenAI
            
            ai_config = self.config.get('ai_providers', {}).get('openai', {})
            llm = ChatOpenAI(
                model_name=ai_config.get('model', 'gpt-4o'),
                openai_api_key=ai_config.get('api_key', ''),
                temperature=0.3
            )
            
            # Task 1: Find all hidden elements
            task_discover = f"""
            Navigate to {url} and analyze the page for hidden elements:
            1. Look for hidden input fields (type="hidden")
            2. Find elements with display:none or visibility:hidden
            3. Locate elements with opacity:0 or off-screen positioning
            4. Check for hidden forms or iframes
            5. List all hidden elements with their names, IDs, and purposes
            """
            
            agent_discover = Agent(task=task_discover, llm=llm)
            discovery_result = await agent_discover.run()
            result_text = str(discovery_result).lower()
            
            logger.info(f"Hidden elements discovery: {result_text[:200]}")
            
            # Check if hidden elements were found
            if any(indicator in result_text for indicator in ['hidden', 'display:none', 'visibility:hidden', 'input type="hidden"']):
                screenshot_url = None
                if hasattr(agent_discover, 'browser') and hasattr(agent_discover.browser, 'page'):
                    screenshot_url = await self.take_screenshot("Hidden_Elements_Discovery", agent_discover.browser.page)
                
                # Task 2: Test hidden elements for manipulation
                xss_payload = payloads.get('xss', ['<script>alert(1)</script>'])[0]
                
                task_test = f"""
                On {url}, test the hidden elements for security issues:
                1. Try to modify hidden input values using browser console
                2. Inject this XSS payload into hidden fields: {xss_payload}
                3. Submit any forms containing hidden elements
                4. Check if manipulated values are accepted by the server
                5. Look for any unexpected behavior or errors
                6. Report if hidden elements can be exploited
                """
                
                agent_test = Agent(task=task_test, llm=llm)
                test_result = await agent_test.run()
                test_text = str(test_result).lower()
                
                # Capture screenshot of test
                if hasattr(agent_test, 'browser') and hasattr(agent_test.browser, 'page'):
                    screenshot_url = await self.take_screenshot("Hidden_Elements_Test", agent_test.browser.page)
                
                # Analyze results
                if any(vuln in test_text for vuln in ['exploited', 'accepted', 'vulnerability', 'manipulated', 'injected']):
                    vulnerabilities.append({
                        'type': 'Hidden Element Manipulation - AI Verified',
                        'severity': 'high',
                        'url': url,
                        'evidence': f'Browser Use AI found exploitable hidden elements: {test_text[:300]}',
                        'description': 'Hidden elements can be manipulated, potentially leading to security bypass or injection attacks',
                        'remediation': 'Validate all input server-side, including hidden fields. Use CSRF tokens and implement proper access controls.',
                        'screenshot': screenshot_url
                    })
                    logger.info(f"AI detected exploitable hidden elements on {url}")
                
                # Task 3: Check for sensitive data in hidden elements
                task_sensitive = f"""
                On {url}, analyze hidden elements for sensitive data exposure:
                1. Examine hidden input values for sensitive information
                2. Look for API keys, tokens, passwords in hidden fields
                3. Check for PII (emails, phone numbers, SSN) in hidden elements
                4. Inspect hidden metadata or configuration
                5. Report any sensitive data found in hidden elements
                """
                
                agent_sensitive = Agent(task=task_sensitive, llm=llm)
                sensitive_result = await agent_sensitive.run()
                sensitive_text = str(sensitive_result).lower()
                
                if any(data in sensitive_text for data in ['api key', 'token', 'password', 'secret', 'credential', 'sensitive']):
                    vulnerabilities.append({
                        'type': 'Sensitive Data in Hidden Elements',
                        'severity': 'critical',
                        'url': url,
                        'evidence': f'Sensitive data found in hidden elements: {sensitive_text[:300]}',
                        'description': 'Hidden elements contain sensitive information accessible via browser inspection',
                        'remediation': 'Never store sensitive data in client-side HTML. Use server-side sessions and secure token management.',
                        'screenshot': screenshot_url
                    })
                    logger.info(f"AI detected sensitive data in hidden elements on {url}")
        
        except Exception as e:
            logger.debug(f"Error in Browser Use hidden elements test: {e}")
        
        return vulnerabilities
    
    async def _test_hidden_elements_with_playwright(self, url: str, payloads: Dict[str, List[str]]) -> List[Dict]:
        """Test hidden elements using Playwright."""
        vulnerabilities = []
        
        try:
            await self.page.goto(url, wait_until='networkidle', timeout=15000)
            
            # Find all hidden elements
            hidden_inputs = await self.page.query_selector_all('input[type="hidden"]')
            hidden_display = await self.page.query_selector_all('[style*="display:none"], [style*="display: none"]')
            hidden_visibility = await self.page.query_selector_all('[style*="visibility:hidden"], [style*="visibility: hidden"]')
            
            all_hidden = hidden_inputs + hidden_display + hidden_visibility
            
            if len(all_hidden) > 0:
                logger.info(f"Found {len(all_hidden)} hidden elements")
                
                # Check for sensitive data in hidden inputs
                for hidden in hidden_inputs[:10]:  # Check first 10
                    try:
                        name = await hidden.get_attribute('name') or 'unnamed'
                        value = await hidden.get_attribute('value') or ''
                        
                        # Check for sensitive patterns
                        sensitive_patterns = ['token', 'key', 'secret', 'password', 'api', 'auth']
                        if any(pattern in name.lower() or pattern in value.lower() for pattern in sensitive_patterns):
                            screenshot_url = await self.take_screenshot(f"Hidden_Sensitive_{name}")
                            
                            vulnerabilities.append({
                                'type': 'Sensitive Data in Hidden Elements',
                                'severity': 'high',
                                'url': url,
                                'parameter': name,
                                'evidence': f'Hidden field "{name}" contains potentially sensitive data',
                                'description': 'Hidden input field contains sensitive information that can be accessed via browser inspection',
                                'remediation': 'Avoid storing sensitive data in hidden fields. Use server-side session management.',
                                'screenshot': screenshot_url
                            })
                            logger.info(f"Found sensitive data in hidden field: {name}")
                        
                        # Try to manipulate hidden field value
                        xss_payload = payloads.get('xss', ['<script>alert(1)</script>'])[0]
                        await self.page.evaluate(f'document.querySelector(\'input[name="{name}"]\').value = "{xss_payload}"')
                        
                    except Exception as e:
                        logger.debug(f"Error checking hidden element: {e}")
                        continue
                
                # Take overall screenshot
                screenshot_url = await self.take_screenshot("Hidden_Elements_Overview")
                
                vulnerabilities.append({
                    'type': 'Hidden Elements Detected',
                    'severity': 'info',
                    'url': url,
                    'evidence': f'Found {len(all_hidden)} hidden elements ({len(hidden_inputs)} hidden inputs)',
                    'description': 'Page contains hidden elements that may be exploitable',
                    'remediation': 'Review all hidden elements for security implications. Validate server-side.',
                    'screenshot': screenshot_url
                })
        
        except Exception as e:
            logger.debug(f"Error testing hidden elements with Playwright: {e}")
        
        return vulnerabilities
    
    async def test_all_browser_vulnerabilities(self, url: str, payloads: Dict[str, List[str]]) -> List[Dict]:
        """Run all browser-based vulnerability tests including hidden elements."""
        all_vulnerabilities = []
        
        try:
            # Initialize browser once
            if not await self.initialize_browser():
                logger.warning("Browser initialization failed, skipping browser tests")
                return all_vulnerabilities
            
            # Test XSS
            if payloads.get('xss'):
                xss_vulns = await self.test_xss_browser(url, payloads['xss'])
                all_vulnerabilities.extend(xss_vulns)
            
            # Test SQL Injection
            if payloads.get('sql_injection'):
                sqli_vulns = await self.test_sqli_browser(url, payloads['sql_injection'])
                all_vulnerabilities.extend(sqli_vulns)
            
            # Test DOM XSS
            dom_xss_vulns = await self.test_dom_xss(url)
            all_vulnerabilities.extend(dom_xss_vulns)
            
            # Test Clickjacking
            clickjacking_vulns = await self.test_clickjacking(url)
            all_vulnerabilities.extend(clickjacking_vulns)
            
            # Test Hidden Elements (NEW)
            hidden_vulns = await self.test_hidden_elements(url, payloads)
            all_vulnerabilities.extend(hidden_vulns)
            
        except Exception as e:
            logger.error(f"Error in browser-based testing: {e}")
        finally:
            await self.close_browser()
        
        return all_vulnerabilities
    
    def test_browser_sync(self, url: str, payloads: Dict[str, List[str]]) -> List[Dict]:
        """Synchronous wrapper for browser testing."""
        try:
            loop = asyncio.get_event_loop()
        except RuntimeError:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
        
        return loop.run_until_complete(
            self.test_all_browser_vulnerabilities(url, payloads)
        )

