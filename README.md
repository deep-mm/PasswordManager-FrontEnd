# PasswordManager-FrontEnd
This is the frontend application for the password manager

This application is Azure AD protected, and ensures the secrets requested can only be accessed by authorized personnel.
The backend of this application is here: [PasswordManager-Backend](https://github.com/deep-mm/PasswordManager-Backend)

![image](https://user-images.githubusercontent.com/29853549/129696728-4db1f043-e0ed-4a08-8459-8151ff2ec81f.png)

This application allows to:
1. View Secrets
2. Add Secrets
3. Delete Secrets
4. Update Secrets

The security part is ensured by 2 factors:
1. Azure AD authentication
2. A master key is required to access the backend api, only if that is available all the secrets can be accessed.
