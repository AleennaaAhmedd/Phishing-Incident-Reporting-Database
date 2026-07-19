
-- STEP 1: CREATE DATABASE

CREATE DATABASE PhishingReportingDB;
USE PhishingReportingDB;


-- STEP 2: CREATE TABLES (DDL - Data Definition Language)


-- Table 1: USER 
CREATE TABLE User_Account (
    UserID      INT PRIMARY KEY,
    Name        VARCHAR(100) NOT NULL,
    Email       VARCHAR(100) NOT NULL UNIQUE,
    Department  VARCHAR(100) NOT NULL,
    Role        VARCHAR(50)  NOT NULL,
    Phone       VARCHAR(20)  UNIQUE,
    JoiningDate DATE         NOT NULL
);

-- Table 2: PHISHING_EMAIL 
CREATE TABLE Phishing_Email (
    EmailID        INT PRIMARY KEY,
    SenderEmail    VARCHAR(150) NOT NULL,
    SenderDomain   VARCHAR(100) NOT NULL,
    Subject        VARCHAR(255) NOT NULL,
    EmailBody      TEXT,
    AttachmentName VARCHAR(150),
    SuspiciousURL  VARCHAR(300),
    ReceivedAt     DATETIME     NOT NULL
);

-- Table 3: ANALYST 
CREATE TABLE Analyst (
    AnalystID          INT PRIMARY KEY,
    Name               VARCHAR(100) NOT NULL,
    Email              VARCHAR(100) NOT NULL UNIQUE,
    Specialization     VARCHAR(100) NOT NULL,
    CertificationLevel VARCHAR(50)  NOT NULL
);

-- Table 4: THREAT_CATEGORY 
CREATE TABLE Threat_Category (
    CategoryID   INT PRIMARY KEY,
    CategoryName VARCHAR(100) NOT NULL UNIQUE,
    Description  VARCHAR(300),
    RiskLevel    VARCHAR(20)  NOT NULL DEFAULT 'Medium'
);

-- Table 5: REPORT 
CREATE TABLE Report (
    ReportID     INT PRIMARY KEY,
    UserID       INT          NOT NULL,
    EmailID      INT          NOT NULL,
    ReportedAt   DATETIME     NOT NULL,
    ReportMethod VARCHAR(50)  NOT NULL DEFAULT 'Email',
    Description  VARCHAR(500),
    Status       VARCHAR(30)  NOT NULL DEFAULT 'Pending',
    FOREIGN KEY (UserID)  REFERENCES User_Account(UserID),
    FOREIGN KEY (EmailID) REFERENCES Phishing_Email(EmailID)
);

-- Table 6: INVESTIGATION 
CREATE TABLE Investigation (
    InvestigationID INT PRIMARY KEY,
    ReportID        INT          NOT NULL,
    AnalystID       INT          NOT NULL,
    StartDate       DATE         NOT NULL,
    EndDate         DATE,
    Verdict         VARCHAR(50),
    ActionTaken     TEXT,
    ThreatLevel     VARCHAR(20)  NOT NULL DEFAULT 'Low',
    FOREIGN KEY (ReportID)  REFERENCES Report(ReportID),
    FOREIGN KEY (AnalystID) REFERENCES Analyst(AnalystID)
);

-- Table 7: EMAIL_CATEGORY 
CREATE TABLE Email_Category (
    EmailCatID   INT PRIMARY KEY,
    EmailID      INT         NOT NULL,
    CategoryID   INT         NOT NULL,
    AssignedBy   VARCHAR(100),
    AssignedDate DATE        NOT NULL,
    FOREIGN KEY (EmailID)    REFERENCES Phishing_Email(EmailID),
    FOREIGN KEY (CategoryID) REFERENCES Threat_Category(CategoryID)
);

-- Table 8: BLACKLIST 
CREATE TABLE Blacklist (
    BlacklistID     INT PRIMARY KEY,
    Domain          VARCHAR(150),
    IPAddress       VARCHAR(50),
    BlacklistedOn   DATE        NOT NULL,
    InvestigationID INT         NOT NULL,
    Reason          VARCHAR(300),
    FOREIGN KEY (InvestigationID) REFERENCES Investigation(InvestigationID)
);


-- STEP 3: INSERT DATA (DML)


-- Threat Categories (8 records)
INSERT INTO Threat_Category VALUES (1, 'Spear Phishing',     'Targeted attack on a specific individual',         'Critical');
INSERT INTO Threat_Category VALUES (2, 'Clone Phishing',     'Copy of a legitimate email with malicious links',  'High');
INSERT INTO Threat_Category VALUES (3, 'Whaling',            'Phishing targeting senior executives',             'Critical');
INSERT INTO Threat_Category VALUES (4, 'Smishing',           'Phishing via SMS messages',                        'Medium');
INSERT INTO Threat_Category VALUES (5, 'Vishing',            'Voice/call-based phishing attack',                 'Medium');
INSERT INTO Threat_Category VALUES (6, 'Pharming',           'Redirecting users to a fake website',              'High');
INSERT INTO Threat_Category VALUES (7, 'Business Email Compromise', 'Impersonating company executives via email', 'Critical');
INSERT INTO Threat_Category VALUES (8, 'Credential Harvesting', 'Fake login pages to steal username/password',   'High');

-- Analysts (8 records)
INSERT INTO Analyst VALUES (1, 'Hamza Tariq',    'hamza.tariq@umt.edu.pk',    'Malware Analysis',        'CEH');
INSERT INTO Analyst VALUES (2, 'Sana Riaz',      'sana.riaz@umt.edu.pk',      'Email Forensics',         'CISSP');
INSERT INTO Analyst VALUES (3, 'Usman Ghani',    'usman.ghani@umt.edu.pk',    'Network Security',        'CompTIA Security+');
INSERT INTO Analyst VALUES (4, 'Nadia Waqar',    'nadia.waqar@umt.edu.pk',    'Threat Intelligence',     'CEH');
INSERT INTO Analyst VALUES (5, 'Fawad Akhtar',   'fawad.akhtar@umt.edu.pk',   'Incident Response',       'CISM');
INSERT INTO Analyst VALUES (6, 'Zara Shahid',    'zara.shahid@umt.edu.pk',    'Social Engineering',      'CISSP');
INSERT INTO Analyst VALUES (7, 'Bilal Mehmood',  'bilal.mehmood@umt.edu.pk',  'Digital Forensics',       'OSCP');
INSERT INTO Analyst VALUES (8, 'Amna Khalid',    'amna.khalid@umt.edu.pk',    'Vulnerability Assessment','CompTIA Security+');

-- Users (25 records)
INSERT INTO User_Account VALUES (1,  'Ali Hassan',       'ali.hassan@umt.edu.pk',       'IT Department',     'Software Engineer',   '0311-1010001', '2022-03-15');
INSERT INTO User_Account VALUES (2,  'Sara Butt',        'sara.butt@umt.edu.pk',         'Finance',           'Accountant',          '0311-1010002', '2021-06-01');
INSERT INTO User_Account VALUES (3,  'Umar Farooq',      'umar.farooq@umt.edu.pk',       'HR Department',     'HR Manager',          '0311-1010003', '2020-01-10');
INSERT INTO User_Account VALUES (4,  'Fatima Malik',     'fatima.malik@umt.edu.pk',      'Administration',    'Admin Officer',       '0311-1010004', '2023-02-20');
INSERT INTO User_Account VALUES (5,  'Bilal Chaudhry',   'bilal.chaudhry@umt.edu.pk',    'IT Department',     'Network Admin',       '0311-1010005', '2021-09-05');
INSERT INTO User_Account VALUES (6,  'Ayesha Khan',      'ayesha.khan@umt.edu.pk',       'Marketing',         'Marketing Executive', '0311-1010006', '2022-11-15');
INSERT INTO User_Account VALUES (7,  'Zain Ahmed',       'zain.ahmed@umt.edu.pk',        'Finance',           'Finance Manager',     '0311-1010007', '2019-07-22');
INSERT INTO User_Account VALUES (8,  'Hira Noor',        'hira.noor@umt.edu.pk',         'Legal',             'Legal Advisor',       '0311-1010008', '2020-04-18');
INSERT INTO User_Account VALUES (9,  'Tariq Mehmood',    'tariq.mehmood@umt.edu.pk',     'Operations',        'Operations Head',     '0311-1010009', '2018-08-30');
INSERT INTO User_Account VALUES (10, 'Nadia Iqbal',      'nadia.iqbal@umt.edu.pk',       'IT Department',     'DBA',                 '0311-1010010', '2023-01-12');
INSERT INTO User_Account VALUES (11, 'Kashif Raza',      'kashif.raza@umt.edu.pk',       'Procurement',       'Procurement Officer', '0311-1010011', '2021-03-25');
INSERT INTO User_Account VALUES (12, 'Maham Arshad',     'maham.arshad@umt.edu.pk',      'Marketing',         'Content Writer',      '0311-1010012', '2022-07-08');
INSERT INTO User_Account VALUES (13, 'Imran Qureshi',    'imran.qureshi@umt.edu.pk',     'Sales',             'Sales Manager',       '0311-1010013', '2020-10-14');
INSERT INTO User_Account VALUES (14, 'Saira Baig',       'saira.baig@umt.edu.pk',        'Administration',    'Secretary',           '0311-1010014', '2022-05-03');
INSERT INTO User_Account VALUES (15, 'Hamza Sheikh',     'hamza.sheikh@umt.edu.pk',      'IT Department',     'System Analyst',      '0311-1010015', '2021-12-19');
INSERT INTO User_Account VALUES (16, 'Sobia Javed',      'sobia.javed@umt.edu.pk',       'HR Department',     'HR Executive',        '0311-1010016', '2023-04-07');
INSERT INTO User_Account VALUES (17, 'Naveed Ali',       'naveed.ali@umt.edu.pk',        'Finance',           'Senior Accountant',   '0311-1010017', '2019-11-28');
INSERT INTO User_Account VALUES (18, 'Amna Zahid',       'amna.zahid@umt.edu.pk',        'Legal',             'Compliance Officer',  '0311-1010018', '2022-08-16');
INSERT INTO User_Account VALUES (19, 'Faisal Latif',     'faisal.latif@umt.edu.pk',      'Sales',             'Sales Executive',     '0311-1010019', '2023-06-11');
INSERT INTO User_Account VALUES (20, 'Rida Chaudhry',    'rida.chaudhry@umt.edu.pk',     'Marketing',         'SEO Specialist',      '0311-1010020', '2021-02-23');
INSERT INTO User_Account VALUES (21, 'Danish Malik',     'danish.malik@umt.edu.pk',      'Operations',        'Operations Executive','0311-1010021', '2020-09-17');
INSERT INTO User_Account VALUES (22, 'Rabia Asif',       'rabia.asif@umt.edu.pk',        'Procurement',       'Procurement Manager', '0311-1010022', '2022-01-30');
INSERT INTO User_Account VALUES (23, 'Kamran Iqbal',     'kamran.iqbal@umt.edu.pk',      'IT Department',     'Web Developer',       '0311-1010023', '2023-03-04');
INSERT INTO User_Account VALUES (24, 'Lubna Farhan',     'lubna.farhan@umt.edu.pk',      'Finance',           'Budget Analyst',      '0311-1010024', '2021-07-14');
INSERT INTO User_Account VALUES (25, 'Shahzad Hussain',  'shahzad.hussain@umt.edu.pk',   'Administration',    'Admin Manager',       '0311-1010025', '2019-05-06');

-- Phishing Emails (30 records)
INSERT INTO Phishing_Email VALUES (1,  'payroll@hbl-bank.secure.com',       'hbl-bank.secure.com',     'Urgent: Verify Your Bank Account Now',                'Dear Employee, your account has been flagged. Click here to verify.',       'AccountVerify.exe',   'http://hbl-fake.login.com',             '2025-01-05 09:15:00');
INSERT INTO Phishing_Email VALUES (2,  'ceo@umtt.edu.pk',                   'umtt.edu.pk',             'Confidential: Wire Transfer Required',                 'Please process an urgent wire transfer of Rs. 500,000 immediately.',        NULL,                  NULL,                                    '2025-01-08 11:30:00');
INSERT INTO Phishing_Email VALUES (3,  'support@micros0ft.com',             'micros0ft.com',           'Your Microsoft Account Will Be Suspended',             'Login now to avoid suspension of your Office 365 account.',                 NULL,                  'http://micros0ft-login.com/verify',     '2025-01-12 14:00:00');
INSERT INTO Phishing_Email VALUES (4,  'noreply@paypal-security.net',       'paypal-security.net',     'PayPal: Unusual Activity Detected',                    'We noticed suspicious login. Verify your account within 24 hours.',         NULL,                  'http://paypal-verify.net/secure',       '2025-01-15 08:45:00');
INSERT INTO Phishing_Email VALUES (5,  'hr@umt-jobs.com',                   'umt-jobs.com',            'Job Offer: Senior Developer Position',                 'Congratulations! You have been selected. Fill in your details to proceed.',  'JobForm.pdf.exe',     'http://umt-jobs.com/apply',             '2025-01-18 10:20:00');
INSERT INTO Phishing_Email VALUES (6,  'admin@fedex-delivery.xyz',          'fedex-delivery.xyz',      'Your Package Could Not Be Delivered',                  'Track your shipment and confirm delivery address by clicking here.',         NULL,                  'http://fedex-fake.xyz/track',           '2025-01-20 13:10:00');
INSERT INTO Phishing_Email VALUES (7,  'it-helpdesk@umt-support.org',       'umt-support.org',         'IT: Password Reset Required Immediately',               'Your UMT password will expire in 2 hours. Reset now to avoid lockout.',      NULL,                  'http://umt-support.org/reset',          '2025-01-25 09:00:00');
INSERT INTO Phishing_Email VALUES (8,  'invoice@vendor-billing.co',         'vendor-billing.co',       'Invoice #INV-2025-441 Payment Due',                    'Please find the attached invoice. Payment due in 3 days.',                  'Invoice441.xlsm',     NULL,                                    '2025-02-01 15:30:00');
INSERT INTO Phishing_Email VALUES (9,  'security@google-accounts.co',       'google-accounts.co',      'Google: Sign-in Attempt Blocked',                      'Someone tried to access your account. Verify your identity now.',            NULL,                  'http://google-accounts.co/verify',     '2025-02-05 12:00:00');
INSERT INTO Phishing_Email VALUES (10, 'alerts@statebank-pk.net',           'statebank-pk.net',        'SBP: KYC Update Required',                             'State Bank of Pakistan requires KYC update. Submit documents within 48hrs.', 'KYCForm.doc',         'http://sbp-kyc.net/update',             '2025-02-08 10:00:00');
INSERT INTO Phishing_Email VALUES (11, 'noreply@jazz-rewards.com',          'jazz-rewards.com',        'You Have Won a Jazz Prize!',                           'Claim your Rs. 50,000 reward! Click the link and enter your CNIC.',          NULL,                  'http://jazz-rewards.com/claim',         '2025-02-10 16:00:00');
INSERT INTO Phishing_Email VALUES (12, 'covid-relief@pakistan-govt.net',    'pakistan-govt.net',       'COVID Relief Fund: Apply Now',                         'Government is distributing relief funds. Apply with your NIC number.',       'ReliefForm.exe',      'http://pakistan-govt.net/apply',        '2025-02-14 08:30:00');
INSERT INTO Phishing_Email VALUES (13, 'cfo@umt-finance.pk',                'umt-finance.pk',          'Urgent: Approve Budget Transfer',                      'CFO needs your approval on the attached budget document urgently.',          'Budget_Q1.xlsm',      NULL,                                    '2025-02-18 11:00:00');
INSERT INTO Phishing_Email VALUES (14, 'support@linkedin-verify.com',       'linkedin-verify.com',     'LinkedIn: Your Account Has Been Restricted',           'Log in to restore your LinkedIn account access.',                           NULL,                  'http://linkedin-verify.com/login',      '2025-02-22 14:30:00');
INSERT INTO Phishing_Email VALUES (15, 'admin@dropbox-share.net',           'dropbox-share.net',       'Shared Document: Q1 Financial Report',                 'Your colleague shared a file. Click to view the Q1 financial report.',       NULL,                  'http://dropbox-share.net/view',         '2025-02-25 09:45:00');
INSERT INTO Phishing_Email VALUES (16, 'noreply@netflix-billing.xyz',       'netflix-billing.xyz',     'Netflix: Payment Failed - Update Card Info',           'Your subscription payment failed. Update payment info to continue.',         NULL,                  'http://netflix-billing.xyz/update',     '2025-03-01 17:00:00');
INSERT INTO Phishing_Email VALUES (17, 'security@amazon-order.co',          'amazon-order.co',         'Amazon: Order Cancelled - Verify Identity',            'Your recent order was cancelled due to suspicious activity.',               NULL,                  'http://amazon-order.co/verify',         '2025-03-05 10:15:00');
INSERT INTO Phishing_Email VALUES (18, 'grant@worldbank-funding.org',       'worldbank-funding.org',   'World Bank Grant: Rs. 2 Million Approved',             'You are eligible for a World Bank grant. Submit your details now.',          'GrantForm.pdf',       'http://worldbank-funding.org/apply',    '2025-03-10 13:20:00');
INSERT INTO Phishing_Email VALUES (19, 'it@umt-security-alert.com',         'umt-security-alert.com',  'Security Alert: Unauthorized Access to Your Email',    'Click here to secure your account immediately and review login history.',    NULL,                  'http://umt-security-alert.com/secure',  '2025-03-14 08:00:00');
INSERT INTO Phishing_Email VALUES (20, 'prize@ufone-win.com',               'ufone-win.com',           'Congratulations! You Won iPhone 15',                   'You have been selected as the lucky winner. Claim your prize today.',         NULL,                  'http://ufone-win.com/claim',            '2025-03-18 12:00:00');
INSERT INTO Phishing_Email VALUES (21, 'verify@nadra-pk.com',               'nadra-pk.com',            'NADRA: CNIC Verification Required',                    'Your CNIC record needs verification. Submit scanned copy urgently.',          'CNICForm.exe',        'http://nadra-pk.com/verify',            '2025-03-22 09:30:00');
INSERT INTO Phishing_Email VALUES (22, 'billing@telenor-update.net',        'telenor-update.net',      'Telenor: Update Your Account to Avoid Suspension',     'Update your Telenor account details within 24 hours to avoid disconnection.', NULL,                 'http://telenor-update.net/login',       '2025-03-26 15:00:00');
INSERT INTO Phishing_Email VALUES (23, 'admin@docusign-secure.xyz',         'docusign-secure.xyz',     'DocuSign: Contract Awaiting Your Signature',           'A contract has been shared with you. Sign now to avoid expiry.',             NULL,                  'http://docusign-secure.xyz/sign',       '2025-04-01 11:10:00');
INSERT INTO Phishing_Email VALUES (24, 'noreply@fbr-tax.net',               'fbr-tax.net',             'FBR: Tax Refund of Rs. 75,000 Pending',                'Federal Board of Revenue has issued a tax refund. Claim within 7 days.',     NULL,                  'http://fbr-tax.net/refund',             '2025-04-05 10:00:00');
INSERT INTO Phishing_Email VALUES (25, 'ceo@partnercompany-pk.com',         'partnercompany-pk.com',   'Confidential Business Proposal',                       'Our company wants to partner with UMT. Review attached proposal urgently.',   'Proposal.exe',        NULL,                                    '2025-04-09 14:00:00');
INSERT INTO Phishing_Email VALUES (26, 'support@zoom-verify.net',           'zoom-verify.net',         'Zoom: Your Account Has Been Suspended',                'Restore your Zoom account by verifying your email and password.',            NULL,                  'http://zoom-verify.net/restore',        '2025-04-13 09:00:00');
INSERT INTO Phishing_Email VALUES (27, 'noreply@whatsapp-verify.org',       'whatsapp-verify.org',     'WhatsApp: Enable Two-Step Verification',               'A new device is trying to access your WhatsApp. Verify now to block.',      NULL,                  'http://whatsapp-verify.org/block',      '2025-04-17 16:30:00');
INSERT INTO Phishing_Email VALUES (28, 'security@hblfintechsupport.com',    'hblfintechsupport.com',   'HBL: Your Card Has Been Temporarily Blocked',          'Unblock your HBL Konnect card by verifying your PIN and CNIC.',             NULL,                  'http://hblfintechsupport.com/unblock',  '2025-04-21 08:45:00');
INSERT INTO Phishing_Email VALUES (29, 'admin@pta-renewal.pk',              'pta-renewal.pk',          'PTA: Mobile Device Registration Expiring',             'Your mobile device registration is expiring. Renew now to avoid blocking.', 'PTAForm.exe',         'http://pta-renewal.pk/renew',           '2025-04-25 11:30:00');
INSERT INTO Phishing_Email VALUES (30, 'noreply@ogra-subsidy.gov.pk.com',   'ogra-subsidy.gov.pk.com', 'OGRA: Fuel Subsidy Registration Open',                 'Register now to receive monthly fuel subsidy from government.',              'SubsidyForm.pdf.exe', 'http://ogra-subsidy.gov.pk.com/apply',  '2025-04-30 13:00:00');

-- Reports (30 records)
INSERT INTO Report VALUES (1,  1,  1,  '2025-01-05 10:00:00', 'Email',          'Received suspicious bank email asking for account details.',   'Under Review');
INSERT INTO Report VALUES (2,  7,  2,  '2025-01-08 12:00:00', 'IT Helpdesk',    'Email claiming to be from CEO requesting wire transfer.',      'Resolved');
INSERT INTO Report VALUES (3,  3,  3,  '2025-01-12 14:30:00', 'Email',          'Got fake Microsoft suspension warning with phishing link.',    'Resolved');
INSERT INTO Report VALUES (4,  2,  4,  '2025-01-15 09:15:00', 'Phone',          'PayPal alert but company does not use PayPal for finance.',    'Under Review');
INSERT INTO Report VALUES (5,  5,  5,  '2025-01-18 11:00:00', 'Email',          'Suspicious job offer email with executable attachment.',       'Resolved');
INSERT INTO Report VALUES (6,  6,  6,  '2025-01-20 13:30:00', 'IT Helpdesk',    'FedEx delivery email but no pending packages expected.',       'Closed');
INSERT INTO Report VALUES (7,  10, 7,  '2025-01-25 09:30:00', 'Email',          'Password reset demand from unknown IT support domain.',        'Resolved');
INSERT INTO Report VALUES (8,  11, 8,  '2025-02-01 16:00:00', 'Email',          'Unknown vendor invoice with macro-enabled Excel attachment.',  'Under Review');
INSERT INTO Report VALUES (9,  4,  9,  '2025-02-05 12:30:00', 'Phone',          'Fake Google security alert asking for credentials.',           'Resolved');
INSERT INTO Report VALUES (10, 17, 10, '2025-02-08 10:30:00', 'IT Helpdesk',    'State Bank KYC update email from unofficial domain.',         'Resolved');
INSERT INTO Report VALUES (11, 20, 11, '2025-02-10 16:30:00', 'Email',          'Jazz prize claim email, company does not run such contests.',  'Closed');
INSERT INTO Report VALUES (12, 12, 12, '2025-02-14 09:00:00', 'Email',          'COVID relief form with suspicious executable file.',           'Resolved');
INSERT INTO Report VALUES (13, 9,  13, '2025-02-18 11:30:00', 'IT Helpdesk',    'Fake CFO email requesting urgent budget approval.',            'Resolved');
INSERT INTO Report VALUES (14, 8,  14, '2025-02-22 15:00:00', 'Email',          'LinkedIn account restriction email with fake login link.',    'Closed');
INSERT INTO Report VALUES (15, 15, 15, '2025-02-25 10:15:00', 'Phone',          'Shared financial document on suspicious Dropbox-like domain.', 'Under Review');
INSERT INTO Report VALUES (16, 16, 16, '2025-03-01 17:30:00', 'Email',          'Netflix billing failure email from unofficial domain.',        'Closed');
INSERT INTO Report VALUES (17, 19, 17, '2025-03-05 10:45:00', 'IT Helpdesk',    'Amazon order cancellation email demanding identity check.',    'Resolved');
INSERT INTO Report VALUES (18, 18, 18, '2025-03-10 13:45:00', 'Email',          'World Bank grant email demanding personal financial info.',    'Resolved');
INSERT INTO Report VALUES (19, 1,  19, '2025-03-14 08:30:00', 'Phone',          'Security alert asking to click link and enter credentials.',   'Under Review');
INSERT INTO Report VALUES (20, 13, 20, '2025-03-18 12:30:00', 'Email',          'Ufone prize winner email asking for bank details.',            'Closed');
INSERT INTO Report VALUES (21, 21, 21, '2025-03-22 10:00:00', 'IT Helpdesk',    'NADRA verification email with suspicious executable.',         'Resolved');
INSERT INTO Report VALUES (22, 22, 22, '2025-03-26 15:30:00', 'Email',          'Telenor account suspension notice from unofficial domain.',    'Resolved');
INSERT INTO Report VALUES (23, 23, 23, '2025-04-01 11:30:00', 'Email',          'DocuSign contract signing request from fake domain.',          'Under Review');
INSERT INTO Report VALUES (24, 24, 24, '2025-04-05 10:30:00', 'IT Helpdesk',    'FBR tax refund email, FBR does not email refund requests.',    'Resolved');
INSERT INTO Report VALUES (25, 25, 25, '2025-04-09 14:30:00', 'Phone',          'Business proposal email with suspicious .exe attachment.',     'Resolved');
INSERT INTO Report VALUES (26, 5,  26, '2025-04-13 09:30:00', 'Email',          'Zoom account suspension email from unofficial Zoom domain.',   'Closed');
INSERT INTO Report VALUES (27, 14, 27, '2025-04-17 17:00:00', 'IT Helpdesk',    'WhatsApp verification from fake whatsapp domain.',            'Under Review');
INSERT INTO Report VALUES (28, 2,  28, '2025-04-21 09:15:00', 'Email',          'HBL card block email asking for PIN and CNIC on a website.',  'Resolved');
INSERT INTO Report VALUES (29, 3,  29, '2025-04-25 12:00:00', 'Email',          'PTA mobile registration renewal with suspicious executable.', 'Under Review');
INSERT INTO Report VALUES (30, 7,  30, '2025-04-30 13:30:00', 'IT Helpdesk',    'OGRA fuel subsidy form with double extension malware file.',   'Resolved');

-- Investigations (20 records)
INSERT INTO Investigation VALUES (1,  2,  2, '2025-01-09', '2025-01-10', 'Confirmed Phishing', 'Email blocked, sender domain blacklisted, user warned',        'Critical');
INSERT INTO Investigation VALUES (2,  3,  1, '2025-01-13', '2025-01-14', 'Confirmed Phishing', 'Fake domain reported to Microsoft, URL blocked on firewall',   'High');
INSERT INTO Investigation VALUES (3,  5,  5, '2025-01-19', '2025-01-20', 'Confirmed Phishing', 'Attachment quarantined, domain blacklisted, HR notified',      'High');
INSERT INTO Investigation VALUES (4,  7,  3, '2025-01-26', '2025-01-27', 'Confirmed Phishing', 'Fake IT domain blocked, password reset issued to user',        'Medium');
INSERT INTO Investigation VALUES (5,  9,  6, '2025-02-06', '2025-02-07', 'Confirmed Phishing', 'Google alerted, fake domain blocked, user awareness session',  'High');
INSERT INTO Investigation VALUES (6,  10, 4, '2025-02-09', '2025-02-10', 'Confirmed Phishing', 'SBP informed, domain blacklisted, staff email sent',           'High');
INSERT INTO Investigation VALUES (7,  12, 7, '2025-02-15', '2025-02-16', 'Confirmed Phishing', 'Malware in attachment confirmed, quarantined immediately',      'Critical');
INSERT INTO Investigation VALUES (8,  13, 2, '2025-02-19', '2025-02-20', 'Confirmed Phishing', 'CEO email spoofing identified, email gateway rules updated',   'Critical');
INSERT INTO Investigation VALUES (9,  17, 8, '2025-03-06', '2025-03-07', 'Confirmed Phishing', 'Amazon spoofed domain reported, URL flagged in system',        'Medium');
INSERT INTO Investigation VALUES (10, 18, 1, '2025-03-11', '2025-03-12', 'Confirmed Phishing', 'World Bank impersonation reported, domain blacklisted',        'Critical');
INSERT INTO Investigation VALUES (11, 21, 5, '2025-03-23', '2025-03-24', 'Confirmed Phishing', 'NADRA impersonation, NADRA notified, executable quarantined',  'High');
INSERT INTO Investigation VALUES (12, 22, 6, '2025-03-27', '2025-03-28', 'Confirmed Phishing', 'Telenor impersonation, domain flagged, users warned',          'Medium');
INSERT INTO Investigation VALUES (13, 24, 3, '2025-04-06', '2025-04-07', 'Confirmed Phishing', 'Fake FBR domain, FBR contacted, domain blocked on firewall',   'High');
INSERT INTO Investigation VALUES (14, 25, 4, '2025-04-10', '2025-04-11', 'Confirmed Phishing', 'Malicious executable in attachment, sender IP blocked',        'Critical');
INSERT INTO Investigation VALUES (15, 28, 7, '2025-04-22', '2025-04-23', 'Confirmed Phishing', 'HBL spoofing, HBL fraud team alerted, domain blacklisted',     'Critical');
INSERT INTO Investigation VALUES (16, 30, 8, '2025-05-01', '2025-05-02', 'Confirmed Phishing', 'Double extension malware, OGRA notified, email filters updated','Critical');
INSERT INTO Investigation VALUES (17, 1,  2, '2025-01-06', NULL,          'Under Investigation', 'Collecting email headers and domain registration data',       'High');
INSERT INTO Investigation VALUES (18, 4,  3, '2025-01-16', NULL,          'Under Investigation', 'Analyzing PayPal-like domain for phishing indicators',        'Medium');
INSERT INTO Investigation VALUES (19, 8,  5, '2025-02-02', NULL,          'Under Investigation', 'Macro-enabled Excel file sent to sandbox for analysis',       'High');
INSERT INTO Investigation VALUES (20, 15, 6, '2025-02-26', NULL,          'Under Investigation', 'Dropbox clone domain under DNS and certificate analysis',     'Medium');

-- Email Categories (25 records)
INSERT INTO Email_Category VALUES (1,  1,  8, 'Sana Riaz',   '2025-01-10');
INSERT INTO Email_Category VALUES (2,  2,  7, 'Hamza Tariq', '2025-01-10');
INSERT INTO Email_Category VALUES (3,  2,  3, 'Hamza Tariq', '2025-01-10');
INSERT INTO Email_Category VALUES (4,  3,  8, 'Usman Ghani', '2025-01-14');
INSERT INTO Email_Category VALUES (5,  5,  1, 'Fawad Akhtar','2025-01-20');
INSERT INTO Email_Category VALUES (6,  7,  8, 'Usman Ghani', '2025-01-27');
INSERT INTO Email_Category VALUES (7,  8,  1, 'Nadia Waqar', '2025-02-03');
INSERT INTO Email_Category VALUES (8,  9,  8, 'Zara Shahid', '2025-02-07');
INSERT INTO Email_Category VALUES (9,  10, 8, 'Nadia Waqar', '2025-02-10');
INSERT INTO Email_Category VALUES (10, 12, 1, 'Bilal Mehmood','2025-02-16');
INSERT INTO Email_Category VALUES (11, 13, 7, 'Sana Riaz',   '2025-02-20');
INSERT INTO Email_Category VALUES (12, 13, 3, 'Sana Riaz',   '2025-02-20');
INSERT INTO Email_Category VALUES (13, 14, 8, 'Zara Shahid', '2025-02-23');
INSERT INTO Email_Category VALUES (14, 15, 2, 'Fawad Akhtar','2025-02-26');
INSERT INTO Email_Category VALUES (15, 17, 2, 'Amna Khalid', '2025-03-07');
INSERT INTO Email_Category VALUES (16, 18, 1, 'Hamza Tariq', '2025-03-12');
INSERT INTO Email_Category VALUES (17, 18, 3, 'Hamza Tariq', '2025-03-12');
INSERT INTO Email_Category VALUES (18, 21, 1, 'Fawad Akhtar','2025-03-24');
INSERT INTO Email_Category VALUES (19, 22, 6, 'Usman Ghani', '2025-03-28');
INSERT INTO Email_Category VALUES (20, 24, 8, 'Nadia Waqar', '2025-04-07');
INSERT INTO Email_Category VALUES (21, 25, 1, 'Nadia Waqar', '2025-04-11');
INSERT INTO Email_Category VALUES (22, 28, 8, 'Bilal Mehmood','2025-04-23');
INSERT INTO Email_Category VALUES (23, 29, 1, 'Amna Khalid', '2025-04-26');
INSERT INTO Email_Category VALUES (24, 30, 1, 'Sana Riaz',   '2025-05-02');
INSERT INTO Email_Category VALUES (25, 4,  8, 'Zara Shahid', '2025-01-17');

-- Blacklist (15 records)
INSERT INTO Blacklist VALUES (1,  'hbl-bank.secure.com',        '203.45.67.89',  '2025-01-11', 17, 'Credential harvesting fake bank site');
INSERT INTO Blacklist VALUES (2,  'umtt.edu.pk',                '192.168.5.100', '2025-01-10', 8,  'CEO spoofing domain used for BEC attack');
INSERT INTO Blacklist VALUES (3,  'micros0ft.com',              '45.33.101.22',  '2025-01-14', 2,  'Typosquat of Microsoft used to harvest logins');
INSERT INTO Blacklist VALUES (4,  'umt-jobs.com',               '78.45.200.11',  '2025-01-20', 3,  'Fake job portal distributing malware');
INSERT INTO Blacklist VALUES (5,  'umt-support.org',            '110.34.56.78',  '2025-01-27', 4,  'Fake IT helpdesk domain for credential theft');
INSERT INTO Blacklist VALUES (6,  'statebank-pk.net',           '60.12.88.44',   '2025-02-10', 6,  'SBP impersonation for KYC credential harvesting');
INSERT INTO Blacklist VALUES (7,  'pakistan-govt.net',          '88.200.45.33',  '2025-02-16', 7,  'Government impersonation distributing malware via form');
INSERT INTO Blacklist VALUES (8,  'umt-finance.pk',             '150.20.30.40',  '2025-02-20', 8,  'Internal finance spoofing domain for BEC attack');
INSERT INTO Blacklist VALUES (9,  'amazon-order.co',            '99.55.12.77',   '2025-03-07', 9,  'Amazon phishing domain redirecting to credential page');
INSERT INTO Blacklist VALUES (10, 'worldbank-funding.org',      '200.11.45.66',  '2025-03-12', 10, 'World Bank impersonation for advance-fee fraud');
INSERT INTO Blacklist VALUES (11, 'nadra-pk.com',               '112.44.88.100', '2025-03-24', 11, 'NADRA impersonation distributing malware via form');
INSERT INTO Blacklist VALUES (12, 'fbr-tax.net',                '180.90.22.55',  '2025-04-07', 13, 'FBR refund scam with credential harvesting page');
INSERT INTO Blacklist VALUES (13, 'partnercompany-pk.com',      '55.200.11.88',  '2025-04-11', 14, 'Malware distribution via fake business proposal');
INSERT INTO Blacklist VALUES (14, 'hblfintechsupport.com',      '77.33.100.22',  '2025-04-23', 15, 'HBL spoofing domain collecting PIN and CNIC data');
INSERT INTO Blacklist VALUES (15, 'ogra-subsidy.gov.pk.com',    '190.80.60.44',  '2025-05-02', 16, 'Double-extension malware disguised as OGRA form');


-- STEP 4: SELECT QUERIES


SELECT * FROM User_Account;
SELECT * FROM Phishing_Email;
SELECT * FROM Report;
SELECT * FROM Investigation;



SELECT EmailID, SenderEmail, SenderDomain, Subject, ReceivedAt
FROM Phishing_Email;


SELECT ReportID, UserID, EmailID, ReportedAt, Status
FROM Report;
SELECT ReportID, Status FROM Report;


SELECT CategoryName, Description, RiskLevel
FROM Threat_Category;


SELECT Name, Specialization, CertificationLevel
FROM Analyst;


-- STEP 5: WHERE CLAUSE


SELECT ReportID, UserID, Status, ReportedAt
FROM Report
WHERE Status = 'Under Review';


SELECT Subject, SenderEmail, SuspiciousURL
FROM Phishing_Email
WHERE SuspiciousURL IS NOT NULL;


SELECT CategoryName, Description
FROM Threat_Category
WHERE RiskLevel = 'Critical';


SELECT InvestigationID, ReportID, AnalystID, StartDate, Verdict
FROM Investigation
WHERE EndDate IS NULL;


-- STEP 6: LOGICAL OPERATORS (AND, OR, NOT, BETWEEN, IN)



SELECT InvestigationID, ThreatLevel, Verdict, ActionTaken
FROM Investigation
WHERE ThreatLevel = 'Critical' AND Verdict = 'Confirmed Phishing';


SELECT ReportID, UserID, ReportMethod, ReportedAt
FROM Report
WHERE ReportMethod = 'Email' OR ReportMethod = 'Phone';


SELECT ReportID, UserID, ReportedAt, Status
FROM Report
WHERE ReportedAt BETWEEN '2025-02-01' AND '2025-02-28';


SELECT Subject, SenderEmail, SenderDomain
FROM Phishing_Email
WHERE SenderDomain IN ('umtt.edu.pk', 'umt-finance.pk', 'hblfintechsupport.com');

SELECT InvestigationID, ReportID, ThreatLevel, Verdict
FROM Investigation
WHERE NOT Verdict = 'Confirmed Phishing';


-- STEP 7: ORDER BY & DISTINCT



SELECT Subject, SenderEmail, ReceivedAt
FROM Phishing_Email
ORDER BY ReceivedAt DESC;


SELECT ReportID, Status, ReportedAt
FROM Report
ORDER BY Status ASC;


SELECT DISTINCT ReportMethod FROM Report;


SELECT DISTINCT ThreatLevel FROM Investigation;


SELECT Name, Department, Role
FROM User_Account
ORDER BY Department ASC, Name ASC;


-- STEP 8: AGGREGATE FUNCTIONS (MIN, MAX, COUNT, SUM, AVG)



SELECT COUNT(*) AS TotalPhishingEmails FROM Phishing_Email;


SELECT COUNT(*) AS TotalReports FROM Report;


SELECT COUNT(*) AS ResolvedReports
FROM Report
WHERE Status = 'Resolved';


SELECT COUNT(*) AS TotalBlacklisted FROM Blacklist;


SELECT MIN(ReceivedAt) AS EarliestEmail, MAX(ReceivedAt) AS LatestEmail
FROM Phishing_Email;


SELECT Status, COUNT(*) AS TotalCount
FROM Report
GROUP BY Status;


-- STEP 9: GROUP BY & HAVING



SELECT SenderDomain, COUNT(*) AS EmailCount
FROM Phishing_Email
GROUP BY SenderDomain
ORDER BY EmailCount DESC;


SELECT UserID, COUNT(*) AS ReportsSubmitted
FROM Report
GROUP BY UserID
ORDER BY ReportsSubmitted DESC;


SELECT AnalystID, COUNT(*) AS InvestigationCount
FROM Investigation
GROUP BY AnalystID
ORDER BY InvestigationCount DESC;


SELECT CategoryID, COUNT(*) AS UsageCount
FROM Email_Category
GROUP BY CategoryID
HAVING COUNT(*) > 2;

SELECT ThreatLevel, COUNT(*) AS Total
FROM Investigation
GROUP BY ThreatLevel
ORDER BY Total DESC;




-- STEP 10: UPDATE & DELETE



UPDATE Report
SET Status = 'Resolved'
WHERE ReportID = 1;


UPDATE Investigation
SET ThreatLevel = 'Critical'
WHERE InvestigationID = 18;


UPDATE Analyst
SET Specialization = 'Advanced Threat Intelligence'
WHERE AnalystID = 4;

-- DELETE 
-- DELETE FROM Report WHERE ReportID = 11 AND Status = 'Closed';
-- DROP TABLE Blacklist;


-- STEP 11: ALTER TABLE (DDL)



ALTER TABLE Phishing_Email 
ADD SeverityScore INT DEFAULT 0;


ALTER TABLE Report 
ADD ReviewedBy VARCHAR(100);


-- STEP 12: JOINS


SELECT u.Name AS Reporter, u.Department, pe.Subject, r.ReportedAt, r.Status
FROM Report r
INNER JOIN User_Account u ON r.UserID = u.UserID
INNER JOIN Phishing_Email pe ON r.EmailID = pe.EmailID;


SELECT i.InvestigationID, a.Name AS Analyst, a.Specialization,
       i.Verdict, i.ThreatLevel, i.ActionTaken
FROM Investigation i
INNER JOIN Analyst a ON i.AnalystID = a.AnalystID;


SELECT u.Name AS Reporter, pe.Subject, pe.SenderEmail,
       r.Status, i.Verdict, i.ThreatLevel
FROM Report r
INNER JOIN User_Account u    ON r.UserID  = u.UserID
INNER JOIN Phishing_Email pe ON r.EmailID = pe.EmailID
INNER JOIN Investigation i   ON r.ReportID = i.ReportID;


SELECT r.ReportID, r.Status, r.ReportedAt,
       i.Verdict, i.ThreatLevel
FROM Report r
LEFT JOIN Investigation i ON r.ReportID = i.ReportID;


SELECT r.ReportID, r.Description, i.InvestigationID,
       i.Verdict, i.StartDate
FROM Report r
RIGHT JOIN Investigation i ON r.ReportID = i.ReportID;


SELECT b.Domain, b.IPAddress, b.BlacklistedOn, b.Reason,
       i.ThreatLevel, a.Name AS InvestigatingAnalyst
FROM Blacklist b
INNER JOIN Investigation i ON b.InvestigationID = i.InvestigationID
INNER JOIN Analyst a ON i.AnalystID = a.AnalystID;


SELECT pe.Subject, pe.SenderDomain, tc.CategoryName, tc.RiskLevel, ec.AssignedBy
FROM Email_Category ec
INNER JOIN Phishing_Email pe   ON ec.EmailID    = pe.EmailID
INNER JOIN Threat_Category tc  ON ec.CategoryID = tc.CategoryID;


SELECT u.Name, u.Department, u.Email
FROM User_Account u
LEFT JOIN Report r ON u.UserID = r.UserID
WHERE r.ReportID IS NULL;

SELECT b.Domain, b.IPAddress, b.Reason, i.ThreatLevel
FROM Blacklist b
INNER JOIN Investigation i ON b.InvestigationID = i.InvestigationID
WHERE i.ThreatLevel = 'Critical';

SELECT r.ReportID, r.Status, i.InvestigationID,i.Verdict
FROM Report r
FULL OUTER JOIN Investigation i
ON r.ReportID = i.ReportID;

SELECT u.Name AS Reporter, u.Department,
       pe.SenderEmail, pe.Subject,
       r.ReportedAt, r.Status,
       i.Verdict, i.ThreatLevel,
       a.Name AS Analyst
FROM Report r
INNER JOIN User_Account u    ON r.UserID       = u.UserID
INNER JOIN Phishing_Email pe ON r.EmailID      = pe.EmailID
LEFT  JOIN Investigation i   ON r.ReportID     = i.ReportID
LEFT  JOIN Analyst a         ON i.AnalystID    = a.AnalystID
ORDER BY r.ReportedAt DESC;
