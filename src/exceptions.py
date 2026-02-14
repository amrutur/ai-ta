# In a new file called exceptions.py (or at the top of agent.py)

class AITAError(Exception):
    """Base class for all exceptions in the AI Teaching Assistant project."""
    pass

class CourseNotFoundError(AITAError):
    """Raised when a requested course_id does not exist in Firestore."""
    def __init__(self, course_id):
        self.course_id = course_id
        self.message = f"Course with ID '{course_id}' was not found in the 'courses' collection in the database."
        super().__init__(self.message)

class StudentNotEnrolledError(AITAError):
    """Raised when a student tries to access a course they aren't part of."""
    def __init__(self, student_id, course_id):
        super().__init__(f"Student {student_id} not found in course {course_id}")