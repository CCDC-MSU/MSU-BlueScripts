function populateAddUserForm(usersData, teamId) {
    const usernameInput = document.getElementById('userUsername');
    const passwordInput = document.getElementById('userPassword');
    const teamSelect = document.querySelector('form[action*="api.admin_add_user"] select[name="team_id"]');
    const addUserButton = document.querySelector('form[action*="api.admin_add_user"] button[type="submit"]');

    if (!usernameInput || !passwordInput || !teamSelect || !addUserButton) {
        console.error("Could not find all required form elements. Make sure you are on the /admin/manage page.");
        return;
    }

    if (!usersData || usersData.length === 0) {
        console.warn("No user data provided.");
        return;
    }

    if (!teamId) {
        console.error("A team ID must be provided to add users.");
        return;
    }

    let userIndex = 0;

    function fillAndLogNextUser() {
        if (userIndex < usersData.length) {
            const [username, password] = usersData[userIndex];
            
            usernameInput.value = username;
            passwordInput.value = password;
            teamSelect.value = teamId;

            // Trigger change events for frameworks like React/Angular that might be listening
            usernameInput.dispatchEvent(new Event('input', { bubbles: true }));
            usernameInput.dispatchEvent(new Event('change', { bubbles: true }));
            passwordInput.dispatchEvent(new Event('input', { bubbles: true }));
            passwordInput.dispatchEvent(new Event('change', { bubbles: true }));
            teamSelect.dispatchEvent(new Event('change', { bubbles: true }));
            
            // If using bootstrap-select, refresh it to show the selected value
            if (window.$ && teamSelect.classList.contains('selectpicker')) {
                $(teamSelect).selectpicker('val', teamId);
            }

            console.log(`Form populated for user: ${username}. Click "Add User" to proceed.`);
            console.log(`To populate the next user, run 'nextUser()' in the console.`);
            window.nextUser = () => {
                userIndex++;
                fillAndLogNextUser();
            };
        } else {
            console.log("All users from the list have been processed.");
            delete window.nextUser; // Clean up the global function
        }
    }
    
    fillAndLogNextUser();
}

// --- HOW TO USE --- This part is for documentation and not part of the executable code.
// 1. **Open your browser's developer console** (F12 or Ctrl+Shift+I).
// 2. **Paste the entire code block above into the console and press Enter.**
// 3. **Prepare your user data and the target team ID:**
//    Example user data:
//    const myUsers = [
//        ['john_doe', 'SecurePassword1'],
//        ['jane_smith', 'AnotherPass!23'],
//        ['bob_client', 'ClientPass#456']
//    ];
//    
//    To find the team ID:
//    - Go to the '/admin/manage' page.
//    - Right-click on the team dropdown in the "Add User" section and select "Inspect".
//    - Look for the `<option>` tags, the `value` attribute is the team ID.
//      e.g., `<option value="1">Red Team</option>` -> teamId would be '1'.
//    const targetTeamId = 'YOUR_TEAM_ID_HERE'; // e.g., '1', '2', etc.
//
// 4. **Run the function with your data:**
//    populateAddUserForm(myUsers, targetTeamId);
//
// 5. **Manually click the "Add User" button on the webpage.**
// 6. **After a successful add, type 'nextUser()' in the console and press Enter** to populate the form with the next user from your list.
//    Repeat steps 5 and 6 until all users are added.
