docker exec -it mailsink sh -c "printf 'Subject: Manual Test\n\nThis is a test body.' | sendmail test@example.com"
