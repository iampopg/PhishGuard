def content_analysis(email_body):
    """Analyze email content for suspicious content."""
    suspicious_keywords = ['login', 'verify', 'password', 'click', 'link', 'account', 'update', 'urgent']
    suspicious_patterns = ['http', 'https', 'www', '.com', '.net', '.org']
    suspicious = False
    reasons = []

    # Check for suspicious keywords
    for keyword in suspicious_keywords:
        if keyword.lower() in email_body.lower():
            suspicious = True
            reasons.append(f"Keyword '{keyword}' found")

    # Check for suspicious patterns
    for pattern in suspicious_patterns:
        if pattern.lower() in email_body.lower():
            suspicious = True
            reasons.append(f"Pattern '{pattern}' found")
    
    return suspicious, reasons
