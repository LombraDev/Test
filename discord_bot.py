"""
Discord Bot for FXAP Decryption
Decrypts FiveM client.lua files encrypted with fxap
"""

import os
import logging
from datetime import datetime
from functools import lru_cache
from io import BytesIO

import discord
from discord.ext import commands
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Set up logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('bot.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# Bot configuration
DISCORD_TOKEN = os.getenv('DISCORD_BOT_TOKEN')
FIVEM_SERVER_KEY = os.getenv('FIVEM_SERVER_KEY')

if not DISCORD_TOKEN:
    raise ValueError("DISCORD_BOT_TOKEN not found in environment variables")

# Bot setup with intents
intents = discord.Intents.default()
intents.message_content = True
bot = commands.Bot(command_prefix='!', intents=intents)


@lru_cache(maxsize=1)
def _get_decryptor(server_key):
    from advanced_fxap_decryptor import FXAPDecryptor

    return FXAPDecryptor(server_key=server_key)


def get_decryptor():
    """Lazily instantiate the decryptor to reduce startup overhead."""
    return _get_decryptor(FIVEM_SERVER_KEY)

@bot.event
async def on_ready():
    """Event triggered when bot is ready"""
    logger.info(f'{bot.user} has connected to Discord!')
    logger.info(f'Bot is in {len(bot.guilds)} guilds')
    
    # Set bot status
    activity = discord.Activity(type=discord.ActivityType.watching, name="for FXAP files")
    await bot.change_presence(activity=activity)

@bot.event
async def on_command_error(ctx, error):
    """Global error handler"""
    if isinstance(error, commands.CommandNotFound):
        await ctx.send("❌ Command not found. Use `!help` to see available commands.")
    elif isinstance(error, commands.MissingRequiredArgument):
        await ctx.send(f"❌ Missing required argument: {error.param}")
    else:
        logger.error(f"Command error: {error}")
        await ctx.send(f"❌ An error occurred: {str(error)}")

@bot.command(name='decrypt', help='Decrypt an FXAP encrypted FiveM client.lua file')
async def decrypt_file(ctx):
    """
    Command to decrypt FXAP encrypted files
    Usage: !decrypt (attach a .lua file)
    """
    # Check if message has attachments
    if not ctx.message.attachments:
        embed = discord.Embed(
            title="❌ No File Attached",
            description="Please attach a `.lua` file to decrypt.\n\n**Usage:** `!decrypt` (with file attachment)",
            color=discord.Color.red()
        )
        await ctx.send(embed=embed)
        return
    
    attachment = ctx.message.attachments[0]
    
    # Validate file
    if not attachment.filename.lower().endswith('.lua'):
        embed = discord.Embed(
            title="❌ Invalid File Type",
            description="Please attach a `.lua` file. Only Lua files are supported.",
            color=discord.Color.red()
        )
        await ctx.send(embed=embed)
        return
    
    # Check file size (limit to 10MB)
    max_size = 10 * 1024 * 1024  # 10MB
    if attachment.size > max_size:
        embed = discord.Embed(
            title="❌ File Too Large",
            description=f"File size ({attachment.size / 1024 / 1024:.1f}MB) exceeds the 10MB limit.",
            color=discord.Color.red()
        )
        await ctx.send(embed=embed)
        return
    
    # Send processing message
    processing_embed = discord.Embed(
        title="🔄 Processing File",
        description=f"Decrypting `{attachment.filename}`...\nThis may take a moment.",
        color=discord.Color.blue()
    )
    processing_msg = await ctx.send(embed=processing_embed)
    
    try:
        file_data = await attachment.read()
        if not file_data:
            embed = discord.Embed(
                title="❌ Empty File",
                description="The attached file contained no data.",
                color=discord.Color.red()
            )
            await processing_msg.edit(embed=embed)
            return

        decryptor = get_decryptor()

        logger.info(f"Processing file: {attachment.filename} ({len(file_data)} bytes)")

        if not decryptor.is_fxap_encrypted(file_data):
            embed = discord.Embed(
                title="ℹ️ File Not Encrypted",
                description="The uploaded file doesn't appear to be FXAP encrypted. It may already be decrypted.",
                color=discord.Color.orange()
            )

            content = file_data.decode('utf-8', errors='ignore')

            if len(content) > 1900:
                output_filename = f"not_encrypted_{attachment.filename}"
                buffer = BytesIO(file_data)
                buffer.seek(0)
                await processing_msg.edit(embed=embed)
                await ctx.send(file=discord.File(buffer, filename=output_filename))
            else:
                embed.add_field(name="File Content Preview", value=f"```lua\n{content[:1900]}\n```", inline=False)
                await processing_msg.edit(embed=embed)
            return

        success, decrypted_content, method_used, error_message = decryptor.decrypt_file_advanced(file_data)

        if success:
            output_filename = f"decrypted_{attachment.filename}"
            buffer = BytesIO(decrypted_content.encode('utf-8'))
            buffer.seek(0)

            embed = discord.Embed(
                title="✅ Decryption Successful",
                description=f"Successfully decrypted `{attachment.filename}`",
                color=discord.Color.green(),
                timestamp=datetime.utcnow()
            )

            embed.add_field(
                name="📊 File Info",
                value=f"**Original Size:** {attachment.size:,} bytes\n"
                      f"**Decrypted Size:** {len(decrypted_content):,} characters\n"
                      f"**Lines:** {decrypted_content.count(chr(10)) + 1:,}\n"
                      f"**Method:** {method_used}",
                inline=True
            )

            if len(decrypted_content) <= 1000:
                embed.add_field(
                    name="📄 Preview",
                    value=f"```lua\n{decrypted_content[:1000]}\n```",
                    inline=False
                )

            embed.set_footer(text="⚠️ Use decrypted files responsibly and respect intellectual property rights")

            await processing_msg.edit(embed=embed)
            await ctx.send(file=discord.File(buffer, filename=output_filename))

        else:
            embed = discord.Embed(
                title="❌ Decryption Failed",
                description=f"Could not decrypt `{attachment.filename}`",
                color=discord.Color.red()
            )

            embed.add_field(
                name="Error Details",
                value=error_message or "Unknown decryption error",
                inline=False
            )

            embed.add_field(
                name="💡 Possible Solutions",
                value="• Ensure the file is properly FXAP encrypted\n"
                      "• Check if you have the correct server key\n"
                      "• Try a different version of the encrypted file\n"
                      "• Contact the resource author for assistance",
                inline=False
            )

            await processing_msg.edit(embed=embed)

    except Exception as e:
        logger.error(f"Error processing file {attachment.filename}: {e}")
        
        error_embed = discord.Embed(
            title="❌ Processing Error",
            description=f"An error occurred while processing `{attachment.filename}`",
            color=discord.Color.red()
        )
        error_embed.add_field(name="Error", value=str(e), inline=False)
        
        await processing_msg.edit(embed=error_embed)

@bot.command(name='help', help='Show help information')
async def help_command(ctx):
    """Custom help command"""
    embed = discord.Embed(
        title="🤖 FXAP Decryptor Bot",
        description="A Discord bot for decrypting FiveM FXAP encrypted client.lua files",
        color=discord.Color.blue()
    )
    
    embed.add_field(
        name="📝 Commands",
        value="`!decrypt` - Decrypt an FXAP encrypted .lua file (attach file)\n"
              "`!batch` - Decrypt multiple files at once (attach multiple files)\n"
              "`!analyze` - Analyze a file without decrypting it\n"
              "`!status` - Show bot status and statistics\n"
              "`!info` - Show bot information\n"
              "`!help` - Show this help message",
        inline=False
    )
    
    embed.add_field(
        name="📋 Usage Instructions",
        value="1. Use the `!decrypt` command\n"
              "2. Attach your encrypted `.lua` file\n"
              "3. Wait for the bot to process the file\n"
              "4. Download the decrypted file",
        inline=False
    )
    
    embed.add_field(
        name="⚠️ Important Notes",
        value="• Only decrypt files you have permission to decrypt\n"
              "• Respect intellectual property rights\n"
              "• File size limit: 10MB\n"
              "• Supported format: FXAP encrypted .lua files",
        inline=False
    )
    
    embed.set_footer(text="Bot created for educational and authorized use only")
    
    await ctx.send(embed=embed)

@bot.command(name='info', help='Show bot information')
async def info_command(ctx):
    """Show bot information"""
    embed = discord.Embed(
        title="ℹ️ Bot Information",
        color=discord.Color.blue()
    )
    
    embed.add_field(
        name="🔧 Version",
        value="1.0.0",
        inline=True
    )
    
    embed.add_field(
        name="🐍 Python Version",
        value=f"{os.sys.version.split()[0]}",
        inline=True
    )
    
    embed.add_field(
        name="📊 Guilds",
        value=f"{len(bot.guilds)}",
        inline=True
    )
    
    embed.add_field(
        name="🔐 Encryption Support",
        value="FXAP (FiveM Asset Protection)",
        inline=False
    )
    
    embed.add_field(
        name="⚡ Features",
        value="• ChaCha20 decryption\n"
              "• XOR fallback decryption\n"
              "• Multiple key derivation attempts\n"
              "• File validation\n"
              "• Detailed error reporting",
        inline=False
    )
    
    await ctx.send(embed=embed)

@bot.command(name='analyze', help='Analyze a file without decrypting it')
async def analyze_file(ctx):
    """
    Analyze an uploaded file to determine encryption type and properties
    """
    if not ctx.message.attachments:
        embed = discord.Embed(
            title="❌ No File Attached",
            description="Please attach a file to analyze.",
            color=discord.Color.red()
        )
        await ctx.send(embed=embed)
        return
    
    attachment = ctx.message.attachments[0]
    
    try:
        file_data = await attachment.read()
        if not file_data:
            await ctx.send("❌ Unable to analyze an empty file.")
            return

        decryptor = get_decryptor()

        encryption_type = decryptor.detect_encryption_type(file_data)
        resource_id = decryptor.extract_resource_id_advanced(file_data)

        embed = discord.Embed(
            title="🔍 File Analysis",
            description=f"Analysis results for `{attachment.filename}`",
            color=discord.Color.blue()
        )

        embed.add_field(
            name="📊 Basic Info",
            value=f"**Size:** {attachment.size:,} bytes\n"
                  f"**Type:** {encryption_type}\n"
                  f"**Resource ID:** {resource_id or 'Not found'}",
            inline=False
        )

        header = file_data[:32]
        embed.add_field(
            name="🔢 File Header (hex)",
            value=f"```{header.hex()[:64]}{'...' if len(header) > 32 else ''}```",
            inline=False
        )

        sample = file_data[:4096] if len(file_data) > 4096 else file_data
        unique_bytes = len(set(sample))
        entropy = unique_bytes / 256.0
        embed.add_field(
            name="📈 Entropy Analysis",
            value=f"**Byte Entropy:** {entropy:.3f}\n"
                  f"**Unique Bytes (sample):** {unique_bytes}/256\n"
                  f"**Likely Encrypted:** {'Yes' if entropy > 0.7 else 'No'}",
            inline=True
        )

        await ctx.send(embed=embed)

    except Exception as e:
        logger.error(f"Error analyzing file: {e}")
        await ctx.send(f"❌ Error analyzing file: {str(e)}")

@bot.command(name='batch', help='Decrypt multiple files at once')
async def batch_decrypt(ctx):
    """
    Decrypt multiple files in a single command
    """
    if not ctx.message.attachments:
        embed = discord.Embed(
            title="❌ No Files Attached",
            description="Please attach one or more `.lua` files to decrypt.",
            color=discord.Color.red()
        )
        await ctx.send(embed=embed)
        return
    
    lua_files = [att for att in ctx.message.attachments if att.filename.lower().endswith('.lua')]
    
    if not lua_files:
        embed = discord.Embed(
            title="❌ No Lua Files Found",
            description="Please attach `.lua` files. Only Lua files are supported.",
            color=discord.Color.red()
        )
        await ctx.send(embed=embed)
        return
    
    if len(lua_files) > 5:
        embed = discord.Embed(
            title="❌ Too Many Files",
            description="Maximum 5 files can be processed at once.",
            color=discord.Color.red()
        )
        await ctx.send(embed=embed)
        return
    
    # Processing message
    processing_embed = discord.Embed(
        title="🔄 Batch Processing",
        description=f"Processing {len(lua_files)} files...",
        color=discord.Color.blue()
    )
    processing_msg = await ctx.send(embed=processing_embed)
    
    results = []
    decryptor = get_decryptor()

    try:
        for i, attachment in enumerate(lua_files):
            progress_embed = discord.Embed(
                title="🔄 Batch Processing",
                description=f"Processing file {i+1}/{len(lua_files)}: `{attachment.filename}`",
                color=discord.Color.blue()
            )
            await processing_msg.edit(embed=progress_embed)

            file_data = await attachment.read()
            if not file_data:
                results.append({
                    'filename': attachment.filename,
                    'success': False,
                    'content': '',
                    'method': '',
                    'error': 'File was empty',
                    'size': 0
                })
                continue

            success, content, method, error = decryptor.decrypt_file_advanced(file_data)
            results.append({
                'filename': attachment.filename,
                'success': success,
                'content': content,
                'method': method,
                'error': error,
                'size': len(content) if success else 0
            })

        # Create results summary
        successful = sum(1 for r in results if r['success'])
        failed = len(results) - successful
        
        summary_embed = discord.Embed(
            title="📊 Batch Processing Complete",
            description=f"Processed {len(lua_files)} files",
            color=discord.Color.green() if failed == 0 else discord.Color.orange()
        )
        
        summary_embed.add_field(
            name="📈 Results",
            value=f"**Successful:** {successful}\n**Failed:** {failed}",
            inline=True
        )
        
        # Add details for each file
        for result in results:
            status = "✅" if result['success'] else "❌"
            method_info = f" ({result['method']})" if result['success'] else ""
            error_info = f" - {result['error']}" if not result['success'] else ""
            
            summary_embed.add_field(
                name=f"{status} {result['filename']}",
                value=f"Size: {result['size']:,} chars{method_info}{error_info}",
                inline=False
            )
        
        await processing_msg.edit(embed=summary_embed)
        
        for result in results:
            if result['success']:
                output_filename = f"decrypted_{result['filename']}"
                buffer = BytesIO(result['content'].encode('utf-8'))
                buffer.seek(0)
                await ctx.send(file=discord.File(buffer, filename=output_filename))
        
    except Exception as e:
        logger.error(f"Batch processing error: {e}")
        error_embed = discord.Embed(
            title="❌ Batch Processing Error",
            description=f"An error occurred during batch processing: {str(e)}",
            color=discord.Color.red()
        )
        await processing_msg.edit(embed=error_embed)

@bot.command(name='status', help='Show bot status and statistics')
async def status_command(ctx):
    """Show bot status and statistics"""
    embed = discord.Embed(
        title="📊 Bot Status",
        color=discord.Color.green()
    )
    
    embed.add_field(
        name="🔗 Connection",
        value="✅ Online",
        inline=True
    )
    
    embed.add_field(
        name="🏠 Guilds",
        value=f"{len(bot.guilds)}",
        inline=True
    )
    
    embed.add_field(
        name="👥 Users",
        value=f"{sum(guild.member_count for guild in bot.guilds)}",
        inline=True
    )
    
    # Bot uptime (simplified)
    embed.add_field(
        name="⏱️ Status",
        value="Running normally",
        inline=False
    )
    
    embed.add_field(
        name="🔧 Supported Methods",
        value="• ChaCha20 decryption\n• AES (ECB/CBC/CTR)\n• XOR decryption\n• Base64 decoding\n• Compression handling\n• Brute force fallback",
        inline=False
    )
    
    await ctx.send(embed=embed)

# Error handling for missing token
if __name__ == "__main__":
    if not DISCORD_TOKEN:
        print("❌ Error: DISCORD_BOT_TOKEN not found in environment variables")
        print("Please create a .env file with your Discord bot token")
        exit(1)
    
    try:
        logger.info("Starting FXAP Decryptor Discord Bot...")
        bot.run(DISCORD_TOKEN)
    except discord.LoginFailure:
        logger.error("❌ Invalid Discord bot token")
    except Exception as e:
        logger.error(f"❌ Bot startup error: {e}")