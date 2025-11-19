# Role Images

This directory contains images for role cards displayed to players when roles are distributed.

## Image Naming Convention

Images should be named using the following pattern:
- Convert role name to lowercase
- Replace spaces with underscores
- Add `.jpg` extension

### Examples:

| Role Name      | Image Filename        |
|----------------|-----------------------|
| Loup blanc     | `loup_blanc.jpg`      |
| Voyante        | `voyante.jpg`         |
| Jester         | `jester.jpg`          |
| Loup Garou     | `loup_garou.jpg`      |
| Developer      | `developer.jpg`       |
| Designer       | `designer.jpg`        |

## Supported Formats

Currently, the system looks for `.jpg` files. You can modify the code in `templates/index.html` to support other formats like `.png` or `.webp`.

## Fallback Behavior

If an image is not found for a role, the system will display the role name on a gradient background instead.

## Recommended Image Specifications

- **Format**: JPG
- **Dimensions**: 800x600 pixels (or any 4:3 ratio)
- **File Size**: Keep under 500KB for faster loading
- **Quality**: High quality, well-lit, clear images work best

## How to Add Images

1. Place your role images in this directory (`/static/images/`)
2. Ensure the filename matches the naming convention above
3. Refresh the browser - images will load automatically when roles are distributed

## Example

For your current roles:
```
static/images/
├── loup_blanc.jpg
├── voyante.jpg
├── jester.jpg
└── loup_garou.jpg
```
