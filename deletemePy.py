import math

# Assuming 'interpolation' is available from the specified import
# from .interpolation import interpolation

class Geometric:
    def __init__(self):
        pass

    def forward_rotate(self, image, theta):
        """Computes the forward rotated image by an angle theta
                image: input image (list of lists representing pixels)
                theta: angle to rotate the image by (in radians)
                return the rotated image (list of lists representing pixels)"""

        # Get image dimensions
        height = len(image)
        width = len(image[0]) if height > 0 else 0

        # Calculate the dimensions of the rotated image
        cos_theta = math.cos(theta)
        sin_theta = math.sin(theta)

        # Calculate the corners of the original image
        corners = [
            [0, 0],
            [width - 1, 0],
            [0, height - 1],
            [width - 1, height - 1]
        ]

        # Rotate the corners
        rotated_corners = []
        for corner in corners:
            x, y = corner # Access elements of the list individually
            new_x = float(x) * cos_theta - float(y) * sin_theta # Convert elements to float
            new_y = float(x) * sin_theta + float(y) * cos_theta # Convert elements to float
            rotated_corners.append([new_x, new_y])

        # Find the new dimensions of the rotated image
        min_x = float('inf')
        min_y = float('inf')
        max_x = float('-inf')
        max_y = float('-inf')

        for x, y in rotated_corners:
            min_x = min(min_x, x)
            min_y = min(min_y, y)
            max_x = max(max_x, x)
            max_y = max(max_y, y)

        new_width = int(math.ceil(max_x - min_x))
        new_height = int(math.ceil(max_y - min_y))

        # Create an empty canvas for the rotated image
        rotated_image = [[0 for _ in range(new_width)] for _ in range(new_height)]

        # Calculate the translation to center the rotated image
        translate_x = -min_x
        translate_y = -min_y

        # Perform the forward rotation
        for y in range(height):
            for x in range(width):
                # Apply rotation and translation
                new_x_float = float(x) * cos_theta - float(y) * sin_theta + translate_x
                new_y_float = float(x) * sin_theta + float(y) * cos_theta + translate_y

                new_x = int(round(new_x_float))
                new_y = int(round(new_y_float))

                # Check if the new coordinates are within the bounds of the rotated image
                if 0 <= new_x < new_width and 0 <= new_y < new_height:
                    rotated_image[new_y][new_x] = image[y][x]

        return rotated_image
    
    # Create a sample image (a simple 2x2 image)
sample_image = [
    [10, 20],
    [30, 40]
]

# Create an instance of the Geometric class
geometric_transformer = Geometric()

# Define the rotation angle (e.g., 45 degrees)
theta = math.pi / 4

# Perform the forward rotation
rotated_image = geometric_transformer.forward_rotate(sample_image, theta)

# Print the rotated image
print("Original Image:")
for row in sample_image:
    print(row)

print("\nRotated Image:")
for row in rotated_image:
    print(row)