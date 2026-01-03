# Tests
cd /workspace/${BRANCH}/gitbackup_test_tools
chmod +x *.sh

# Make test user
./1_make_testuser.sh

# Wait until /workspace/production/overleafserver/data_gitbackup/downloads/ is ready
./2_get_empty_testuser_project_list.sh

# The admin user needs a project, otherwise we can not down load a project....
./3_get_other_user_project_list.sh llm@lmm.lmm

