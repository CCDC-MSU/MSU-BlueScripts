// ==UserScript==
// @name         Scoring Engine Bulk User Add
// @namespace    http://tampermonkey.net/ 
// @version      0.1
// @description  Adds a UI to bulk add users from CSV data on the admin/manage page.
// @author       Gemini
// @match        */admin/manage
// @grant        none
// ==/UserScript==

(function() {
    'use strict';

    // 1. Create the UI Panel
    const panel = document.createElement('div');
    panel.className = 'card';
    panel.innerHTML = "`
        <h4 class=\"text-center\">Bulk Add Users</h4>
        <div style=\"padding: 15px;">
            <div class=\"form-group\">
                <label for=\"teamSelectBulk\">Team for new users:</label>
                <select class=\"selectpicker\" name=\"team_id_bulk\" data-width=\"100%\" id=\"teamSelectBulk\"></select>
            </div>
            <div class=\"form-group\">
                <label for=\"csvData\">Paste CSV Data (username,password):</label>
                <textarea id=\"csvData\" class=\"form-control\" rows=\"10\" placeholder=\"user1,password123\nuser2,password456\"></textarea>
            </div>
            <button id=\"startBulkAdd\" class=\"btn btn-success center-block\">Start Bulk Add</button>
            <div id=\"bulkLog\" style=\"margin-top: 15px; background-color: #f0f0f0; padding: 10px; border-radius: 4px; height: 150px; overflow-y: scroll;\"></div>
        </div>
    ";

    // 2. Insert the panel onto the page
    const addUserCard = document.querySelector('form[action*="api.admin_add_user"]').closest('.card');
    if (addUserCard && addUserCard.parentNode) {
        addUserCard.parentNode.insertBefore(panel, addUserCard.nextSibling);
    }


    // 3. Populate the new team selector from the existing "Add User" form's team list
    const originalTeamSelect = document.querySelector('select[name="team_id"]');
    const bulkTeamSelect = document.getElementById('teamSelectBulk');
    if (originalTeamSelect) {
        bulkTeamSelect.innerHTML = originalTeamSelect.innerHTML;
        // We need to re-initialize the bootstrap-select picker for the new dropdown
        if (window.$) {
            $(bulkTeamSelect).selectpicker('refresh');
        }
    }

    // 4. Add logic to the "Start Bulk Add" button
    const startButton = document.getElementById('startBulkAdd');
    const csvDataTextArea = document.getElementById('csvData');
    const logDiv = document.getElementById('bulkLog');

    function log(message) {
        logDiv.innerHTML += message + '<br>';
        logDiv.scrollTop = logDiv.scrollHeight;
    }

    async function addUser(username, password, teamId) {
        const formData = new FormData();
        formData.append('username', username);
        formData.append('password', password);
        formData.append('team_id', teamId);

        try {
            const response = await fetch('/api/admin/add_user', {
                method: 'POST',
                body: new URLSearchParams(formData) // Correctly format as x-www-form-urlencoded
            });
            const result = await response.json();
            if (result.status && result.status === 'success') {
                log(`SUCCESS: Added user ${username}.`);
            } else {
                log(`ERROR: Failed to add ${username}. Server response: ${JSON.stringify(result)}`);
            }
        } catch (error) {
            log(`ERROR: Exception when adding ${username}: ${error}`);
        }
    }

    startButton.addEventListener('click', async () => {
        const csvData = csvDataTextArea.value.trim();
        const selectedTeamId = bulkTeamSelect.value;

        if (!csvData) {
            log('ERROR: CSV data is empty.');
            return;
        }
        if (!selectedTeamId) {
            log('ERROR: No team selected.');
            return;
        }

        log('Starting bulk add process...');
        startButton.disabled = true;

        const lines = csvData.split('\n').filter(line => line.trim() !== '');

        for (const line of lines) {
            const parts = line.split(',');
            if (parts.length !== 2) {
                log(`WARNING: Skipping invalid line: ${line}`);
                continue;
            }
            const username = parts[0].trim();
            const password = parts[1].trim();
            await addUser(username, password, selectedTeamId);
            await new Promise(resolve => setTimeout(resolve, 200)); // Small delay between requests
        }

        log('Bulk add process finished.');
        startButton.disabled = false;
        log('Reloading page in 5 seconds to reflect changes...');
        setTimeout(() => {
            window.location.reload();
        }, 5000);
    });

})();
