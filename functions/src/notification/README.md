# Setup for email notifications

1) Sign up for a SendGrid account.
2) In Sendgrid, verify android-security@google.com as a sender by completing Single Sender Verification. If decide to use another email address, change the "from" field in code accordingly.
3) Create and and store a SendGrid API key.
4) Set the key as an  environment variable in cloud fuctions. In /functions, run: 
  ```sh
  $ firebase functions:config:set sendgrid.key="THE API KEY" 
  ```