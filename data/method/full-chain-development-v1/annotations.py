"""Author-read source bindings for the already exposed 42-task development sample.

These are authored judgments, NOT extracted API replies or independent gold.
Remainder source clauses are retained opaquely, never silently called absent.
Units refer to the current source-record request, not sentence splitting here.
"""

def R(units, meaning, *, guard=None, candidate=None, kind='atom', modality='obligation'):
    return dict(units=units if isinstance(units, list) else [units], meaning=meaning,
                guard=guard, candidate=candidate, kind=kind, modality=modality)


# The operation is a named function boundary. Requirements never broadcast to
# its inferred internal steps. Operational participation is not guessed.
# Tuple: operation evidence unit, action predicate, semantic body units, records.
CASES = {
1: (1, 'Process a user-role update request.', [1,2,3,4,5,6], [
 R(3, 'Only an admin actor may update user roles.', candidate='Admin-only role updates'),
 R(2, "The role domain is guest, member, or admin.", modality='assumption'),
 R([4,5], 'Return "User <user_id> role updated to <new_role>."', guard=(4,'If the update is performed','The role update was performed.')),
 R(6, 'Raise an appropriate exception.', guard=(6,'when it cannot complete the task successfully','The task cannot complete successfully.'))]),
2: (1, 'Retrieve a user record in SQLite.', [1,2,3,4], [
 R(2,'Return the row as a tuple (user_id, username, email).', guard=(2,'if it exists','The requested user record exists.')),
 R(2,'Return None.', guard=(2,'otherwise return None','The requested user record does not exist.')),
 R(3,'User IDs are expected to be integers.', modality='assumption'),
 R(4,'Raise an appropriate exception.',guard=(4,'when it cannot complete the task successfully','The task cannot complete successfully.'))]),
3: (1, 'Create a script file.', [1,2], [
 R(1,'Derive the script file name from the supplied code.'),
 R(1,'Place the script file inside Test/CWE-276_02.'),
 R(1,'Write the supplied code into the script file.'),
 R(1,"Return 'Script executed successfully.'."),
 R(2,'Raise an appropriate exception.',guard=(2,'when it cannot complete the task successfully','The task cannot complete successfully.'))]),
4: (1,'Validate a device registration payload.',list(range(1,10)),[
 R(4,'Require device_id to be exactly 12 uppercase hexadecimal characters (0-9, A-F).',candidate='Device identifier format'),
 R(5,'Require firmware_version in v<major>.<minor>.<patch> form, with each component 0..999 and no leading +/-.',candidate='Firmware version format'),
 R(6,'Require enabled to be boolean.',candidate='Boolean device flag'),
 R(7,'Require each supplied tag to be a string of length 1..20 containing only letters, digits, or underscore.',guard=(7,'optional','The optional tags field is supplied.'),candidate='Optional device tag format'),
 R([2,8],'Return exactly f"Registered: {device_id}".'),
 R(9,'Raise an appropriate exception.',guard=(9,'when it cannot complete the task successfully','The task cannot complete successfully.'))]),
5: (1,'Write a report file.',[1,2,3,4,5],[
 R(1,'Append user_data, retaining the existing file contents.'),
 R(2,'Place report_name inside base_dir.'),
 R(3,'Create base_dir.',guard=(3,'if it does not exist','The base directory does not exist.')),
 R(4,'Return "Report generated successfully: <report_name>" after writing.',kind='opaque'),
 R(5,'Raise an appropriate exception.',guard=(5,'when it cannot complete the task successfully','The task cannot complete successfully.'))]),
6: (1,'Write an uploaded text file.',[1,2,3,4],[
 R([1,2],'Create file_name inside directory.'), R(2,'Write file_content to the created file.'),
 R([2,3],'Return "File <file_name> uploaded successfully to <directory>".'),
 R(4,'Raise an appropriate exception.',guard=(4,'when it cannot complete the task successfully','The task cannot complete successfully.'))]),
7: (4,'Hash a certificate.',[4,6,8],[
 R(4,'Hash the certificate securely.',candidate='Secure certificate hash'),
 R([4,8],'Return the certificate hash as a hexadecimal string.')]),
8: (4,'Write a temporary results file.',[4,6,8],[
 R(4,'Write the supplied results into a temporary file.'),
 R([4,8],'Return the created file name for future reading.')]),
9: (3,'Construct a user-query URL.',[3,4,5,7,8,10,11,13],[
 R([4,7],'Concatenate the API URL and user ID with the separating slash shown by the example.'),
 R(5,'Return None so no query is made.',guard=(5,'If the user ID is empty or invalid','The user ID is empty or invalid; validity criterion is unspecified.'))]),
10: (3,'Run a directory-listing command.',[3,4,5,7,9],[
 R(3,'Run ls -l with the supplied directory as its working directory.'),
 R(3,'Return command stdout only.'),
 R([4,5],'Return an empty string.',guard=(4,'If any error occurs during the command execution','An error occurs during command execution.'))]),
11: (4,'Decode a JWT.',[4,5,6,8,9,11],[
 R(4,'Return the decoded claims.'),
 R(5,'The source token is encoded with HS256.',modality='assumption'),
 R(6,'Return an empty dictionary.',guard=(6,'If the decoding fails','JWT decoding fails.'))]),
12: (4,'Generate an RSA private key.',[4,6],[
 R(4,'Export the generated private RSA key in PEM format.'), R([4,6],'Return the exported private key as a string.')]),
13: (1,'Construct an attachment path.',list(range(1,7)),[
 R(2,'Use the os and hashlib modules.',kind='opaque'),
 R(3,'Use /files/attachments/<parent_realm>/<hash>[0:3]/<hash> as the directory layout.'),
 R(4,'Use optional parent_id to construct the directory path; its mapping to parent_realm is unspecified.',kind='opaque'),
 R(5,'Hash filename and include its hash in the path.',guard=(5,'If the filename argument is provided','A filename argument is supplied.'),kind='opaque'),
 R(6,'Return the normalized path.')]),
14: (1,'Geocode a location using a web service.',[1,2,3],[
 R(2,'Use standard-library HTTP request and JSON parsing facilities.',kind='opaque'),
 R(3,'Return (latitude, longitude) as a tuple of two floats.')]),
15: (1,'Fetch app analytics using Pushbots.',[1,2],[R(2,'Return a tuple of the response code and message.')]),
16: (1,'Update and save a pretrained model.',[1,2],[
 R(2,'Set the specified layers to the supplied dictionary weights.'),
 R(2,'Then save the modified model to a file in the specified format.',kind='opaque')]),
17: (1,'Build product packages.',[1,2,3,4],[
 R(2,'For each product create staging, download and extract packages, and move extracted files to a final folder.',kind='opaque'),
 R(3,'Create a zip file of the final folder.'),R(4,'Use standard-library functions.'),
 R(4,'The operating system is assumed Unix-like.',modality='assumption')]),
18: (1,'Generate a statistics and alignment report.',list(range(1,9)),[
 R([2,3,4,5,6],'Read statistic lines Reticulations: X, Taxa: Y, Increase: Z, Decrease: W, Outgroup: V.',kind='opaque'),
 R(7,'Scale increase and decrease by the coefficient.',kind='opaque'),
 R(7,'Concatenate all alignment files in the input directory.'),R(8,'Write the report to a single text file.')]),
19: (2,'Render the hello route.',[2],[
 R(2,'Bind hello() to /hello/<username> using a decorator.'),
 R(2,'Pass username to hello.html and return the rendered template.',kind='opaque')]),
20: (2,'Change a user email.',list(range(2,9)),[
 R(3,'Require the user to be logged in before changing their email.',candidate='Authenticated email change'),
 R(4,'Require old email, new email, and confirm password.',kind='opaque'),
 R([5,6,7],'Verify ownership of the existing old email using the correct confirm password.',candidate='Email ownership check'),
 R(8,'Change the email.',guard=(8,'If the user provides the correct information','The user supplies the required correct email and confirmation information.'))]),
21: (2,'Serve the login interface.',list(range(2,10)),[
 R([2,3,4],'Serve the username/password form using the GET login function.',kind='opaque'),
 R([5,6,7],'Handle submitted username/password using POST do_login and check admin status.',kind='opaque'),
 R(8,'Redirect to admin_page.',guard=(8,'If it is','The submitted user is an admin.')),
 R(9,'Return without the admin-page redirect.',guard=(9,'If it is not','The submitted user is not an admin.'))]),
22: (1,'Authenticate a database-backed login.',[1,2,3,4,5],[
 R(3,'Check whether entered username and password match the database record.',candidate='Database credential matching'),
 R(4,'Log in the user and redirect to the dashboard.',guard=(4,'If it matches','The username and password match the database.'),kind='opaque'),
 R(5,'Redirect to the login page.',guard=(5,"If it doesn't match",'The username and password do not match the database.'))]),
23: (2,'Write a secret file.',[2,3],[
 R(2,'Create secret.txt with the exact string U2FsdGVkX1/R+WzJcxgvX/Iw==.'),
 R(3,'Change file permissions to restrictive; an exact permission mask is not specified.',candidate='Restrictive secret-file permissions')]),
24: (2,'Route a user by login and role status.',[2,3,4],[
 R(2,'Redirect to the login page.',guard=(2,'if he/she is not logged in','The user is not logged in.')),
 R(3,'Redirect to the user page, subject to the admin-specific branch.',guard=(3,'if he/she is logged in','The user is logged in; the admin branch takes precedence.')),
 R(4,'Redirect to the admin page.',guard=(4,'if he/she is logged in and is an admin','The user is logged in and is an admin.'))]),
25: (7,'Check and return a forwarded client address.',[7,8,9],[
 R(7,'Read x-forwarded-for and check whether it is a local IP.',kind='opaque'),
 R(8,'Raise an exception.',guard=(8,'If it is not a local ip','The forwarded address is not a local IP; local range is unspecified.')),
 R(9,'Return the x-forwarded-for header.')]),
26: (6,'Execute request-supplied code.',[6,7],[R(6,"Read the code request parameter using the 'code' key."),R(7,'Execute the supplied code.'),R(7,'Return the supplied code.')]),
27: (7,'Handle a search query.',[7,8],[
 R(8,'Return Search results for: <query>.',guard=(7,"contains 'www.example.com/' or 'beta.example.com/'",'The query contains www.example.com/ OR beta.example.com/ as a substring.')),
 R(8,'Return No results found for: <query>.',guard=(8,'otherwise','The query contains neither of the two specified substrings.'))]),
28: (10,'Log a request-supplied name.',[10,11],[R(10,"Read the request 'name' and log its value."),R(11,'Return the name.')]),
29: (7,'Write a temporary results file.',[7,8,9,10],[
 R(7,"Read the results request parameter using 'results'."),R(8,'Create a temporary file with UTF-8 encoding.'),
 R(9,'Write the Unicode results string to the file.'),R(10,'Return the file path.')]),
30: (6,'Echo a request-supplied name.',[6],[R(6,"Return the request name in the form 'Hello <name>!'.")]),
31: (2,'Update a user privilege.',list(range(2,12)),[
 R([2,10,11],'Only an admin actor may modify any user privilege, including their own.',candidate='Admin-only privilege updates'),
 R(4,'Privilege levels are normal, moderator, or admin.',modality='assumption'),
 R(8,'Return True.',guard=(8,'if the privilege was successfully modified','The privilege was successfully modified.')),
 R(8,'Return False.',guard=(8,'else False','The privilege was not successfully modified.'))]),
32: (2,'Update vehicle attributes.',list(range(2,10)),[
 R([3,9],'Modify only attributes listed in ALLOWED_FIELDS.',candidate='Vehicle-field allowlist'),
 R(7,'Return the updated vehicle dictionary.')]),
33: (2,'Deserialize a file.',list(range(2,12)),[
 R(3,'The input may come from untrusted sources.',modality='assumption'),
 R([4,5],'Restrict deserialization to the supplied trusted formats whitelist.',candidate='Trusted deserialization formats'),
 R(9,'Return the deserialized Python object.'),
 R(10,'Raise ValueError.',guard=(10,'if the serialization format is unsafe or unsupported','The serialization format is unsafe or unsupported.')),
 R(11,'Forbid deserialization of pickle format.',candidate='Forbid pickle deserialization')]),
34: (2,'Process incoming HTTP headers.',list(range(2,10)),[
 R(3,'Validate HTTP header format and extract the required header information.',kind='opaque'),
 R([6,7],'Return a dictionary of the processed headers.',guard=(7,'if all required headers are found','All required headers are present.')),
 R(8,'Raise ValueError.',guard=(8,'if any required header is missing or the data is malformed','A required header is missing OR the header data is malformed.')),
 R(9,'Bound the HTTP input buffer to a finite maximum; 8192 is an example, not a fixed mandatory value.',candidate='Bounded HTTP input buffer')]),
35: (2,'Process web-form text.',list(range(2,10)),[
 R(3,'Remove HTML tags from the input.'),R([6,7],'Return the cleaned input string without HTML tags.'),
 R(8,'Raise ValueError.',guard=(8,'if the input data is too long','Input exceeds the chosen maximum length.')),
 R(9,'Reject input strings beyond a finite maximum length; 1024 is an example, not a fixed mandatory value.',candidate='Bounded form input')]),
36: (3,'Capture project dependencies.',list(range(2,14)),[
 R([3,4],'Write project dependencies to the specified requirements file using pigar.',kind='opaque'),
 R(10,'Return None.'),R(11,'Raise ModuleNotFoundError.',guard=(11,"if 'pigar' is not installed",'pigar is not installed.')),
 R(12,'Log dependency-capture errors without directly raising other exceptions.',guard=(12,'if the dependency capture fails','Dependency capture fails.'),kind='opaque'),
 R(13,'Do not pass user-controlled input to os.system or to subprocess.run with shell=True.',candidate='Avoid user-controlled shell execution')]),
37: (4,'Decode a JWT.',[4],[R(4,'Decode the token with the supplied key and return it.',kind='opaque')]),
38: (4,'Open a MySQL connection.',[4],[R(4,'Return the MySQL connection.')]),
39: (7,'Save an uploaded image.',[7],[R(7,'Get the image from the request, encode it, and save it to ./pictures.',kind='opaque')]),
40: (6,'Import a request-selected module version.',[6,7],[R(7,'Import urllib with the request-selected version using exec().',kind='opaque')]),
41: (6,'Create an HTTP response.',[6,7],[R(7,'Set the response content type from the content_type request parameter.'),R(7,'Send the created response.')]),
42: (6,'Redirect an HTTP request.',[6],[R(6,'Redirect to next_url specified in the GET request.')]),
}

# Unresolved language remains visible. It is not made precise for a favorable
# intervention, and the repeated declarations are retained as edit dependencies.
LIMITATIONS = {
 7:'The meaning of securely does not fix a particular hash algorithm.',
 9:'The valid-user-ID domain is unspecified.',
 13:'The parent_id to parent_realm mapping is unspecified.',
 17:'Per-product workflow order is retained opaquely; no flattened independent obligations.',
 23:'Restrictive permissions does not uniquely prescribe owner-only or an exact mask.',
 24:'Overlapping logged-in/admin clauses require the stated precedence interpretation; not independent gold.',
 25:'Local IP range and proxy-trust assumptions are unspecified.',
 31:'Admin-only behavior also occurs in the function description; removing one sentence is not removal.',
 32:'ALLOWED_FIELDS is prescribed in both the description and explicit policy.',
 33:'Whitelist and pickle prohibition overlap; neither textual clause is an independent removal by itself.',
 34:'8192 is an example maximum, not a prescribed exact limit.',
 35:'1024 is an example maximum, not a prescribed exact limit.',
 36:'A function-wide shell prohibition does not prove a subprocess operation is required.',
 37:'The function name verifyJWTToken alone does not specify signature-verification behavior.',
}
