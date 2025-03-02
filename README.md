
## Security Application

This security application is designed to maintain a safe and compliant environment by allowing users to upload evidence, which is then analyzed for obscene content. Administrators can manage user warnings and track allowance limits through a dedicated dashboard.

## Features



- Evidence Upload with Media Processing
- Image Analysis for Obscene Content
- User Authentication and Session Management
- Admin Dashboard for User and Evidence Management
- Automated Warning Emails to Users
- Lost & Found Section
## Installation

Clone the repository

```bash
  git clone https://github.com/your-repo/security-application.git
```
Install dependencies:
    
```bash
  npm install
```
Set up environment variables in a .env file:

```bash
EMAIL_USER=your-email@gmail.com
EMAIL_PASS=your-email-password
DB_HOST=localhost
DB_USER=root
DB_PASS=password
DB_NAME=security_db
```
Run the application:

```bash
npm start
```
## Authors

- [@NischayVerma](https://www.github.com/NischayVerma21)




## Tech Stack


***Backend***: Node.js, Express

***Database***: MySQL

***Email Service***: Nodemailer (Gmail SMTP)


