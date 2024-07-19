import pandas as pd
import ast
import gradio as gr
import bcrypt
import os

# Constants for file paths
USER_DATA_FILE = 'C:\\Users\\hp\\Desktop\\online\\users.xlsx'
JOB_DATA_FILE = 'C:\\Users\\hp\\Desktop\\online\\job and skills.xlsx'
APPLICATIONS_FILE = 'C:\\Users\\hp\\Desktop\\online\\applications.xlsx'

# Load the updated dataset from the Excel file
def load_data(file_path):
    return pd.read_excel(file_path)

df = load_data(JOB_DATA_FILE)

# Print the column names to debug
print("Columns in the dataframe:", df.columns.tolist())

# Function to safely evaluate the string representation of lists to actual lists
def safe_literal_eval(x):
    try:
        return ast.literal_eval(x) if isinstance(x, str) else []
    except (ValueError, SyntaxError):
        return []

# Check if 'skill' column exists before applying transformations
if 'skill' in df.columns:
    # Convert the 'skill' column from string representation of lists to actual lists
    df['skill'] = df['skill'].apply(safe_literal_eval)
else:
    print("The column 'skill' does not exist in the DataFrame. Please check the column name.")

# Function to load users from the Excel file
def load_users():
    try:
        users_df = pd.read_excel(USER_DATA_FILE)
        return {row['username']: row['password'] for _, row in users_df.iterrows()}
    except FileNotFoundError:
        return {}

# Function to save users to the Excel file
def save_user(username, hashed_password):
    users_df = pd.DataFrame(load_users().items(), columns=['username', 'password'])
    new_user = pd.DataFrame([[username, hashed_password]], columns=['username', 'password'])
    updated_users_df = pd.concat([users_df, new_user], ignore_index=True)
    updated_users_df.to_excel(USER_DATA_FILE, index=False)

# Load users from the Excel file
users_db = load_users()
sessions = {}

def hash_password(password):
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

def check_password(hashed_password, plain_password):
    return bcrypt.checkpw(plain_password.encode('utf-8'), hashed_password.encode('utf-8'))

def signup(username, password):
    try:
        if username in users_db:
            return "Username already exists."
        hashed_password = hash_password(password)
        users_db[username] = hashed_password
        save_user(username, hashed_password)
        return "User signed up successfully."
    except Exception as e:
        return f"Error during sign up: {str(e)}"

def login(username, password):
    try:
        if username not in users_db:
            return "Username does not exist."
        if check_password(users_db[username], password):
            sessions[username] = True
            return "Login successful."
        else:
            return "Incorrect password."
    except Exception as e:
        return f"Error during login: {str(e)}"

def logout(username):
    try:
        if username in sessions:
            del sessions[username]
            return "Logout successful."
        else:
            return "User not logged in."
    except Exception as e:
        return f"Error during logout: {str(e)}"

def match_skills(user_skills, job_skills):
    user_skills_lower = [skill.lower() for skill in user_skills]
    job_skills_lower = [skill.lower() for skill in job_skills]
    return len(set(user_skills_lower) & set(job_skills_lower))

def find_matching_jobs(user_input, username):
    try:
        if username not in sessions:
            return {"error": "Please log in to see matching jobs."}
        
        print(f"User {username} is searching for jobs with skills: {user_input}")
        user_skills = [skill.strip() for skill in user_input.split(',')]
        print(f"Parsed user skills: {user_skills}")
        
        if len(user_skills) > 5:
            return {"error": "Please enter up to 5 skills."}

        if 'skill' not in df.columns:
            return {"error": "The column 'skill' does not exist in the DataFrame. Please check the column name in your Excel file."}

        # Find matching jobs
        df['match_score'] = df['skill'].apply(lambda job_skills: match_skills(user_skills, job_skills))
        matching_jobs = df[df['match_score'] > 0].sort_values(by='match_score', ascending=False).head(50)
        
        print(f"Number of matching jobs found: {len(matching_jobs)}")
        print(matching_jobs[['title', 'match_score']])  # Displaying titles and match scores for debug

        if matching_jobs.empty:
            return {"message": "Sorry, we don't have any jobs matching these skills."}

        results = []
        for index, row in matching_jobs.iterrows():
            job_info = {
                "Job Title": row['title'],
                "Skills": ', '.join(row['skill']),
                "Company Name": row['company_name'],
                "Job Type": row['schedule_type'],
                "Location": row['location'],
                "Description": row['description'],
                "Extensions": row['extensions'],
                "Match Score": row['match_score'],
                "Job ID": index  # Using the index as Job ID for applying to jobs
            }
            results.append(job_info)
        print(f"Found {len(results)} matching jobs for user {username}")
        return results
    except Exception as e:
        return {"error": f"Error during job search: {str(e)}"}

def apply_for_job(name, email, job_id, username, user_input_skills):
    try:
        # Get job details
        job = df.iloc[int(job_id)]
        application = {
            "Applicant Name": name,
            "Applicant Email": email,
            "Job Title": job['title'],
            "Company Name": job['company_name'],
            "Location": job['location'],
            "Description": job['description'],
            "Job Skills": ', '.join(job['skill']),
            "User Skills": user_input_skills,
            "Username": username
        }
        # Save application
        applications_file_path = APPLICATIONS_FILE
        if os.path.exists(applications_file_path):
            applications_df = pd.read_excel(applications_file_path)
            applications_df = pd.concat([applications_df, pd.DataFrame([application])], ignore_index=True)
        else:
            applications_df = pd.DataFrame([application])
        applications_df.to_excel(applications_file_path, index=False)
        return f"Application submitted for job: {job['title']} at {job['company_name']}"
    except Exception as e:
        return f"Error during job application: {str(e)}"

# Create Gradio Interfaces for Authentication
signup_interface = gr.Interface(
    fn=signup,
    inputs=[gr.Textbox(label="Username"), gr.Textbox(label="Password", type="password")],
    outputs="text",
    title="Sign Up"
)

login_interface = gr.Interface(
    fn=login,
    inputs=[gr.Textbox(label="Username"), gr.Textbox(label="Password", type="password")],
    outputs="text",
    title="Login"
)

logout_interface = gr.Interface(
    fn=logout,
    inputs=[gr.Textbox(label="Username")],
    outputs="text",
    title="Logout"
)

# Main Job Matching Interface
job_matching_interface = gr.Interface(
    fn=find_matching_jobs,
    inputs=[gr.Textbox(lines=2, placeholder="Enter your skills (comma separated, up to 5)"), gr.Textbox(label="Username")],
    outputs=gr.JSON(label="Matching Jobs"),
    title="Job Matching App",
   description="Enter your skills to find matching jobs"
)

# Job Application Interface
job_application_interface = gr.Interface(
    fn=apply_for_job,
    inputs=[gr.Textbox(label="Name"), gr.Textbox(label="Email"), gr.Textbox(label="Job ID"), gr.Textbox(label="Username"), gr.Textbox(label="User Input Skills")],
    outputs="text",
    title="Apply for Job",
    description="Enter your details to apply for a job"
)

# Combine Interfaces
iface = gr.TabbedInterface(
    [signup_interface, login_interface, logout_interface, job_matching_interface, job_application_interface], 
    ["Sign Up", "Login", "Logout", "Job Matching", "Apply for Job"]
)

# Launch the interface with sharing enabled
if __name__ == "__main__":
    iface.launch(share=True)
