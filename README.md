# Vulnerability Management System

A comprehensive web application for consolidating and managing vulnerability data from multiple security tools (Wiz, Veracode, Arctic Wolf, Crowdstrike, Burp). The system provides centralized tracking, status management, Jira integration, and robust reporting capabilities.

## Features

### Core Functionality
- **Multi-Source Vulnerability Consolidation**: Import and consolidate vulnerabilities from:
  - Wiz (CSV and API)
  - Veracode (XML detailed reports and API)
  - Arctic Wolf (CSV and API)
  - Crowdstrike (planned)
  - Burp (planned)

- **Complete Vulnerability Lifecycle Management**:
  - Track vulnerabilities through multiple states: open, false-positive, risk-accepted, in-progress, resolved, delayed, POAMd
  - Full revision history for all field changes
  - Assignment to teams and individuals
  - Environment tracking (Dev, Stage, Test, Production)

- **Jira Cloud Integration**:
  - Automatic ticket creation for vulnerabilities
  - Bulk ticket creation
  - Ticket status synchronization
  - Comment management

- **Advanced Filtering & Reporting**:
  - Filter by severity, status, environment, date ranges, assignee, CVE
  - Group vulnerabilities by CVE
  - Executive dashboards and CIO reports
  - Trend analysis
  - Aging reports
  - Team-based reporting
  - CSV export capabilities

- **Authentication & Authorization**:
  - User/password authentication
  - JWT token support for API access
  - Role-based access control (admin, security-engineer, analyst, sre, viewer)

### Tech Stack
- **Backend**: Python Flask with SQLAlchemy ORM
- **Database**: SQLite (easily upgradeable to PostgreSQL/MySQL)
- **Frontend**: HTML5, CSS3, Vanilla JavaScript
- **Containerization**: Docker & Docker Compose
- **Integrations**: Jira Cloud API

## Quick Start

### Prerequisites
- Docker and Docker Compose installed
- (Optional) Jira Cloud account and API token for ticket integration

### Installation

1. Clone the repository:
   ```bash
   git clone <repository-url>
   cd funOtimeSCP
   ```

2. Create a `.env` file from the example:
   ```bash
   cp .env.example .env
   ```

3. Edit `.env` and configure your settings:
   ```bash
   # Required: Change these secrets!
   SECRET_KEY=your-secret-key-here
   JWT_SECRET_KEY=your-jwt-secret-key-here

   # Optional: Jira Integration
   JIRA_URL=https://your-org.atlassian.net
   JIRA_EMAIL=your-email@example.com
   JIRA_API_TOKEN=your-jira-api-token
   JIRA_PROJECT_KEY=VULN

   # Optional: Admin credentials
   ADMIN_EMAIL=admin@example.com
   ADMIN_PASSWORD=change-me-in-production
   ```

4. Start the application:
   ```bash
   docker-compose up -d
   ```

5. Access the application:
   ```
   http://localhost:5000
   ```

6. Login with default credentials:
   - Username: `admin`
   - Password: `admin` (or value from .env)
   - **Important**: Change the password immediately after first login!

## User Roles & Workflows

### User Group A: Security Engineers
**Responsibilities**: Vulnerability ingestion and initial triage

**Workflow**:
1. Import vulnerability data from security tools via the Import page
2. Review newly imported vulnerabilities
3. Perform initial triage (mark false positives, assign to teams)
4. Create Jira tickets for validated vulnerabilities
5. Set due dates and priorities

### User Group B: Analysts & Security Managers
**Responsibilities**: Reporting and metrics

**Workflow**:
1. Access the Reports page for comprehensive analytics
2. Generate executive summaries and CIO reports
3. Track remediation trends and team performance
4. Export data for presentations
5. Monitor aging vulnerabilities

**Available Reports**:
- Summary Report: High-level overview with severity/status breakdown
- Trend Analysis: New vs. resolved vulnerabilities over time
- Team Performance: Vulnerabilities by assigned team
- Aging Report: Open vulnerabilities by age buckets
- CIO Report: Executive summary with key metrics

### User Group C: SRE & Software Engineering Teams
**Responsibilities**: Review assigned vulnerabilities and remediate

**Workflow**:
1. View assigned vulnerabilities filtered by team
2. Review Jira tickets linked to vulnerabilities
3. Update status as work progresses
4. Add remediation notes
5. Mark vulnerabilities as resolved when fixed

## Importing Vulnerability Data

### Wiz
1. Export vulnerabilities from Wiz console as CSV
2. Go to Import page → Select "Wiz"
3. Upload the CSV file
4. Review import results

**Expected CSV columns**: Issue ID, Title, Severity, Status, Resource, CVE, CVSS, First Detected, Description

### Veracode
1. Export detailed report from Veracode as XML
2. Go to Import page → Select "Veracode"
3. Upload the XML file
4. Review import results

**Supported format**: Veracode Detailed Report XML (detailedreport.xsd)

### Arctic Wolf
1. Export vulnerability data from Arctic Wolf console as CSV
2. Go to Import page → Select "Arctic Wolf"
3. Upload the CSV file
4. Review import results

**Expected CSV columns**: Alert ID, Title, Severity, Status, Asset, CVE, CVSS Score, Created Date, Description

## API Documentation

### Authentication

All API endpoints (except login/register) require JWT authentication.

**Login**:
```bash
curl -X POST http://localhost:5000/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username": "admin", "password": "admin"}'
```

**Use the token in subsequent requests**:
```bash
curl -X GET http://localhost:5000/api/vulnerabilities \
  -H "Authorization: Bearer YOUR_ACCESS_TOKEN"
```

### Key Endpoints

**Vulnerabilities**:
- `GET /api/vulnerabilities` - List vulnerabilities (with filtering)
- `GET /api/vulnerabilities/<id>` - Get vulnerability details
- `PUT /api/vulnerabilities/<id>` - Update vulnerability
- `GET /api/vulnerabilities/stats` - Get statistics

**Jira Integration**:
- `POST /api/jira/create/<vuln_id>` - Create Jira ticket
- `POST /api/jira/bulk-create` - Create multiple tickets
- `POST /api/jira/sync/<ticket_id>` - Sync ticket status

**Reports**:
- `GET /api/reports/summary` - Summary report
- `GET /api/reports/trends?days=90` - Trend analysis
- `GET /api/reports/cio` - CIO executive report
- `GET /api/reports/export/csv` - Export to CSV

**Import**:
- `POST /api/import/wiz` - Import Wiz data
- `POST /api/import/veracode` - Import Veracode data
- `POST /api/import/arctic-wolf` - Import Arctic Wolf data

## Vulnerability Status Workflow

The system supports the following vulnerability statuses:

- **open**: Newly discovered, awaiting triage
- **in-progress**: Actively being remediated
- **resolved**: Vulnerability has been fixed
- **false-positive**: Determined to be a false positive
- **risk-accepted**: Risk has been formally accepted
- **delayed**: Remediation postponed
- **poamd**: Under a Plan of Action & Milestones

## Database Schema

### Core Tables
- **vulnerabilities**: Main vulnerability records with current state
- **vulnerability_history**: Complete audit trail of all changes
- **users**: User accounts and roles
- **jira_tickets**: Jira ticket tracking
- **vulnerability_sources**: Data source configuration and sync status

## Security Considerations

1. **Change Default Credentials**: Immediately change the default admin password
2. **Secure Secrets**: Use strong, unique values for SECRET_KEY and JWT_SECRET_KEY
3. **HTTPS**: Deploy behind a reverse proxy with HTTPS in production
4. **API Keys**: Store API keys securely in environment variables
5. **Regular Updates**: Keep dependencies updated
6. **Backup**: Regularly backup the database volume

## Production Deployment

### Using PostgreSQL (Recommended for Production)

1. Update `.env`:
   ```bash
   DATABASE_URL=postgresql://user:password@db:5432/vulndb
   ```

2. Update `docker-compose.yml`:
   ```yaml
   services:
     db:
       image: postgres:15
       environment:
         POSTGRES_DB: vulndb
         POSTGRES_USER: vulnuser
         POSTGRES_PASSWORD: change-me
       volumes:
         - postgres-data:/var/lib/postgresql/data

     vuln-management:
       depends_on:
         - db
       environment:
         - DATABASE_URL=postgresql://vulnuser:change-me@db:5432/vulndb

   volumes:
     postgres-data:
   ```

### Reverse Proxy (Nginx)

Example Nginx configuration:
```nginx
server {
    listen 80;
    server_name vuln.example.com;

    location / {
        proxy_pass http://localhost:5000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

## Troubleshooting

### Database Issues
```bash
# Reset database (WARNING: Deletes all data)
docker-compose down -v
docker-compose up -d
```

### View Logs
```bash
docker-compose logs -f
```

### Access Container Shell
```bash
docker-compose exec vuln-management bash
```

### Common Issues

**Import fails**: Check file format matches expected columns
**Jira integration fails**: Verify API token and permissions
**Login issues**: Check database was initialized correctly

## StephensonStellar Design

The application features a sophisticated color scheme inspired by StephensonStellar:
- **Primary**: Deep blues (#0A1628, #1E3A5F, #2C5282)
- **Accent**: Gold (#D4AF37) and Silver (#C0C0C0)
- **Status Colors**: Semantic colors for vulnerability severity

## Support & Contributing

For issues, questions, or contributions, please refer to the project repository.

## License

This project is provided as-is for vulnerability management purposes.

## Acknowledgments

Built to consolidate vulnerability data from industry-leading security tools and provide a unified view for security operations teams.
