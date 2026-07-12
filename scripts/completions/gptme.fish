# Fish completion for rig - no file fallback for options

# Cache variables to avoid repeated expensive calls
set -g __rig_models_cache ""
set -g __rig_tools_cache ""
set -g __rig_conversations_cache ""
set -g __rig_cache_time 0

# Helper function to check if cache is fresh (5 minutes)
function __rig_cache_fresh
    set -l current_time (date +%s)
    test (math $current_time - $__rig_cache_time) -lt 300
end

# Dynamic model completion using rig-util
function __rig_models
    if not __rig_cache_fresh; or test -z "$__rig_models_cache"
        set -l models_list (rig-util models list --simple 2>/dev/null)

        # Fallback to common models if command fails
        if test -z "$models_list"
            set models_list "openai/gpt-4o openai/gpt-4o-mini anthropic/claude-sonnet-4-6 anthropic/claude-haiku-4-5 anthropic/claude-opus-4-6"
        end

        set -g __rig_models_cache (string join " " $models_list)
        set -g __rig_cache_time (date +%s)
    end
    string split " " $__rig_models_cache
end

# Fast tools completion - use common tools
function __rig_tools
    if test -z "$__rig_tools_cache"
        set -g __rig_tools_cache "shell ipython browser patch save read append screenshot vision tmux gh computer rag chats"
    end
    string split " " $__rig_tools_cache
end

# Fast conversation completion - only load when actually needed
function __rig_conversations
    if not __rig_cache_fresh; or test -z "$__rig_conversations_cache"
        set -g __rig_conversations_cache (rig-util chats ls -n 20 2>/dev/null | grep -E "^[0-9]" | awk '{print $1}' | string join " ")
        set -g __rig_cache_time (date +%s)
    end
    string split " " $__rig_conversations_cache
end

# Clear default completions
complete -c rig -e

# Model completion - no file fallback
complete -c rig -s m -l model -x -a "(__rig_models)" -d "Model to use"

# Tools completion - no file fallback
complete -c rig -s t -l tools -x -a "(__rig_tools)" -d "Tools to allow"

# Name completion - no file fallback
complete -c rig -l name -x -a "(__rig_conversations)" -d "Conversation name"

# System completion - no file fallback
complete -c rig -l system -x -a "full short" -d "System prompt"

# Tool format completion - no file fallback
complete -c rig -l tool-format -x -a "markdown xml tool" -d "Tool format"

# Workspace directory completion (allow directories)
complete -c rig -s w -l workspace -x -a "(__fish_complete_directories)" -d "Workspace directory"

# Boolean flags (no arguments)
complete -c rig -s r -l resume -f -d "Load last conversation"
complete -c rig -s y -l no-confirm -f -d "Skip confirmation prompts"
complete -c rig -s n -l non-interactive -f -d "Non-interactive mode"
complete -c rig -l no-stream -f -d "Don't stream responses"
complete -c rig -l show-hidden -f -d "Show hidden system messages"
complete -c rig -s v -l verbose -f -d "Verbose output"
complete -c rig -l version -f -d "Show version"
complete -c rig -s h -l help -f -d "Show help"

# File path completion for arguments (prompts can be file paths)
complete -c rig -a "(__fish_complete_path)"
