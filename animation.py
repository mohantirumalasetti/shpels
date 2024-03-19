from PIL import Image, ImageDraw
import imageio
import math

def create_loading_mask(frames, output_path='loading_mask.gif', size=(100, 100), duration=0.1):
    images = []

    for i in range(frames):
        # Create a blank image with an alpha channel (RGBA)
        img = Image.new('RGBA', size, (0, 0, 0, 0))

        # Draw a rotating line
        draw = ImageDraw.Draw(img)
        center = (size[0] // 2, size[1] // 2)
        line_length = min(size) // 4
        angle = math.radians(i * (360 / frames))
        end_point = (center[0] + line_length * math.cos(angle),
                     center[1] + line_length * math.sin(angle))
        draw.line([center, end_point], fill=(0, 0, 255, 128), width=3)

        # Append the image to the list
        images.append(img)

    # Save the images as an animated GIF with loop parameter set to 0 (infinite loop)
    imageio.mimsave(output_path, images, duration=duration, loop=0)

if __name__ == "__main__":
    create_loading_mask(frames=20)
    print("Loading mask animation created and saved as loading_mask.gif")
    