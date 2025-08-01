# Folder Comparison Tool
A powerful, multi-threaded folder comparison application built with Python and CustomTkinter, uses SHA-256 to compare any changes between folders recursively.

<img width="956" height="1024" alt="image" src="https://github.com/user-attachments/assets/ad6a0227-78ae-4729-a3ef-985a4d33c588" />


## Requirements

- Python 3.7 or above
- CustomTkinter
- psutil

## Usage
### Basic Workflow

- Select Original Folder: Choose your original/reference folder
- Select New Folder: Choose the folder to compare against
- Choose Output File: Specify where to save results (e.g., result.txt)
- Configure Options: Set your preferences using checkboxes
- Adjust Performance: Tune thread count and chunk size for your system
- Start Comparison: Click "Start Comparison" and monitor progress

### Configuration Options
#### Output Options

- Append Mode: Add results to existing file instead of overwriting
- Include Prefixes: Add changed:, added:, removed: prefixes to results
- Enable Logging: Generate detailed log.log file with performance metrics

#### Performance Settings

- Thread Count: Number of parallel processing threads, these are more dependent on disk speed than CPU cores.
- Chunk Size: Memory chunk size in MB for file processing (default: 64MB) (Higher is better for larger files and more system memory)

## Output Format
Without Prefixes
```
"D:\Unity\Assets\Scripts\PlayerController.cs"
"D:\Unity\Assets\Textures\player_sprite.png"
"D:\Unity\Assets\Audio\jump_sound.wav"
```
With Prefixes

```
changed: "D:\Unity\Assets\Scripts\PlayerController.cs"
added: "D:\Unity\Assets\Textures\new_texture.png"
removed: "D:\Unity\Assets\Audio\old_sound.wav"
```
