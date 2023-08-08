# Sardonyx-Server
The server of Sardonyx.
# Credits
Credits to [@tnix100](https://github.com/tnix100) for help with server setup and security.

Credits to [Meower Media Co](https://github.com/meower-media-co) for help with bcrypt.
# Documentation
**Note:** This documentation is a work in progress. Some details may be innacurate, or not helpful.
### signup 
*Tags: authentication* 

Example: `{"ask":"signup","username":"Sardonyx","password":"MySecretPassword"}` 

This action creates a new account and automatically authenticates you. 
### login
*Tags: authentication* 

Example: `{"ask":"login","username":"Sardonyx","password":"MySecretPassword"}` 

This action authenticates you. 
### post 
*Tags: requires-auth* 

Example: `{"ask":"post","msg":"Hello world!"}` 

This action will send a new post. 
### get_posts 
*Tags: requires-auth* 

Example: `{"ask":"get_posts"}` 

This action will get the 10 most recent posts. 
### get_user 
*Tags: requires-auth* 

Example: `{"ask":"get_user","username":"Sardonyx"}` 

This action will return a user's profile. 
### ban 
*Tags: requires-state, requires-auth* 

Example: `{"ask":"ban","username":"ABadPerson"}` 

This action will ban a user. 
### kick 
*Tags: requires-state, requires-auth* 

Example: `{"ask":"kick","username":"ABadPerson"}` 

This action will kick a user. 
### report_post 
*Tags: safety, requires-auth* 

Example: `{"ask":"report_post","id":"unique-post-id","reason":"This post violates the Terms of Service by..."}` 

This action will report a post. 
### get_post 
*Tags: requires-auth* 

Example: `{"ask":"get_post","id":"unique-post-id"}` 

This action will get a specific post by ID. 
### get_reports 
*Tags: requires-state, requires-auth* 

Example: `{"ask":"get_reports","id":"unique-post-id"}` 

This action will get the reports of a post. 
### get_user_state
*Tags: requires-auth*

Example: `{"ask":"get_user_state","username":"Sardonyx"}` 

This action will return a user's state. 
### set_bio
*Tags: requires-auth*

Example: `{"ask":"set_bio","bio":"Hello world!"}` 

This action will update the currently authenticated user's bio.