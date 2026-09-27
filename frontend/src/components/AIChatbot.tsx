import React, { useState, useEffect, useRef } from 'react';
import { useNavigate } from 'react-router-dom';
import {
  ChatMessage,
  ChatResponse,
  ChatSuggestedAction,
  getChatPrompts,
  sendChatMessage,
} from '../services/api';

interface DisplayMessage extends ChatMessage {
  id: string;
  responseMeta?: ChatResponse;
  isError?: boolean;
}

export const AIChatbot: React.FC = () => {
  const navigate = useNavigate();
  const [isOpen, setIsOpen] = useState(false);
  const [isMinimized, setIsMinimized] = useState(false);
  const [inputMessage, setInputMessage] = useState('');
  const [loading, setLoading] = useState(false);
  const [starterPrompts, setStarterPrompts] = useState<string[]>([]);
  const [messages, setMessages] = useState<DisplayMessage[]>([
    {
      id: 'welcome-1',
      role: 'assistant',
      content:
        "👋 **Hello! I'm your ScamBuster AI Security Assistant.**\n\nI can help you:\n- **Triage suspicious messages, SMS, or emails**\n- **Check links, phone numbers, and APKs for scam tactics**\n- **Provide emergency steps if you suspect your account is compromised**\n\nPaste any text below or choose a starter question!",
      timestamp: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
    },
  ]);

  const messagesEndRef = useRef<HTMLDivElement>(null);
  const inputRef = useRef<HTMLInputElement>(null);

  // Load starter prompts
  useEffect(() => {
    getChatPrompts()
      .then((prompts) => {
        if (prompts && prompts.length > 0) {
          setStarterPrompts(prompts);
        }
      })
      .catch(() => {
        setStarterPrompts([
          '🚨 Someone asked for my OTP — is it a scam?',
          '🔍 Analyze this message: "Your account is locked, click to verify"',
          '📱 How can I tell if an APK download has hidden spyware?',
          '💸 I transferred money to a caller. What are my emergency steps?',
        ]);
      });
  }, []);

  // Auto-scroll on new message
  useEffect(() => {
    if (isOpen && !isMinimized) {
      messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' });
    }
  }, [messages, isOpen, isMinimized]);

  // Focus input on open
  useEffect(() => {
    if (isOpen && !isMinimized) {
      setTimeout(() => inputRef.current?.focus(), 150);
    }
  }, [isOpen, isMinimized]);

  const handleSend = async (textToSend?: string) => {
    const text = (textToSend || inputMessage).trim();
    if (!text || loading) return;

    const userMsgId = `user-${Date.now()}`;
    const userMsg: DisplayMessage = {
      id: userMsgId,
      role: 'user',
      content: text,
      timestamp: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
    };

    setMessages((prev) => [...prev, userMsg]);
    setInputMessage('');
    setLoading(true);

    try {
      // Build conversation history (excluding initial welcome greeting)
      const historyPayload: ChatMessage[] = messages
        .filter((m) => m.id !== 'welcome-1' && !m.isError)
        .slice(-6)
        .map((m) => ({ role: m.role, content: m.content }));

      const res = await sendChatMessage(text, historyPayload);

      const botMsg: DisplayMessage = {
        id: `bot-${Date.now()}`,
        role: 'assistant',
        content: res.reply,
        responseMeta: res,
        timestamp: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
      };

      setMessages((prev) => [...prev, botMsg]);
    } catch (err: any) {
      const errorMsg: DisplayMessage = {
        id: `err-${Date.now()}`,
        role: 'assistant',
        content:
          "⚠️ **I couldn't reach the cybersecurity assistant backend.** Please make sure the ScamBuster API is running on localhost:8000.",
        isError: true,
        timestamp: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
      };
      setMessages((prev) => [...prev, errorMsg]);
    } finally {
      setLoading(false);
    }
  };

  const handleActionClick = (action: ChatSuggestedAction) => {
    if (action.action_type === 'navigate' || action.action_type === 'scan') {
      navigate(action.target);
    }
  };

  const handleClearHistory = () => {
    setMessages([
      {
        id: `welcome-${Date.now()}`,
        role: 'assistant',
        content:
          "✨ **Chat history cleared.** Ready for your next cybersecurity question or suspicious message analysis!",
        timestamp: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
      },
    ]);
  };

  const renderFormattedContent = (content: string) => {
    // Custom lightweight markdown renderer for clean security alerts
    const lines = content.split('\n');

    return (
      <div className="space-y-1.5 text-sm leading-relaxed">
        {lines.map((line, idx) => {
          const trimmed = line.trim();
          if (!trimmed) {
            return <div key={idx} className="h-1" />;
          }

          // Headers
          if (trimmed.startsWith('### ')) {
            return (
              <h4 key={idx} className="font-bold text-base text-brand-600 dark:text-brand-400 mt-2 mb-1 flex items-center gap-1.5">
                {trimmed.replace('### ', '').replace(/\*\*/g, '')}
              </h4>
            );
          }
          if (trimmed.startsWith('#### ')) {
            return (
              <h5 key={idx} className="font-semibold text-sm text-slate-800 dark:text-slate-200 mt-2 mb-0.5">
                {trimmed.replace('#### ', '').replace(/\*\*/g, '')}
              </h5>
            );
          }

          // Bullet points
          if (trimmed.startsWith('- ') || trimmed.startsWith('* ')) {
            const bulletText = trimmed.substring(2);
            return (
              <div key={idx} className="flex items-start gap-2 ml-1 text-slate-700 dark:text-slate-300">
                <span className="text-brand-500 font-bold mt-0.5">•</span>
                <span>{renderInlineFormatting(bulletText)}</span>
              </div>
            );
          }

          // Numbered lists
          if (/^\d+\.\s/.test(trimmed)) {
            const listMatch = trimmed.match(/^(\d+)\.\s(.*)$/);
            const num = listMatch ? listMatch[1] : '1';
            const itemText = listMatch ? listMatch[2] : trimmed;
            return (
              <div key={idx} className="flex items-start gap-2 ml-1 text-slate-700 dark:text-slate-300">
                <span className="text-brand-600 dark:text-brand-400 font-semibold min-w-[1.2rem] text-xs mt-0.5">
                  {num}.
                </span>
                <span>{renderInlineFormatting(itemText)}</span>
              </div>
            );
          }

          // Blockquote
          if (trimmed.startsWith('> ')) {
            return (
              <div
                key={idx}
                className="pl-3 py-1 border-l-2 border-amber-500 bg-amber-500/10 text-amber-800 dark:text-amber-200 text-xs rounded-r my-1"
              >
                {renderInlineFormatting(trimmed.substring(2))}
              </div>
            );
          }

          // Standard paragraph
          return (
            <p key={idx} className="text-slate-700 dark:text-slate-300">
              {renderInlineFormatting(trimmed)}
            </p>
          );
        })}
      </div>
    );
  };

  const renderInlineFormatting = (text: string) => {
    // Process **bold** and `code`
    const parts = text.split(/(\*\*.*?\*\*|`.*?`)/g);

    return parts.map((part, i) => {
      if (part.startsWith('**') && part.endsWith('**')) {
        return (
          <strong key={i} className="font-semibold text-slate-900 dark:text-white">
            {part.slice(2, -2)}
          </strong>
        );
      }
      if (part.startsWith('`') && part.endsWith('`')) {
        return (
          <code
            key={i}
            className="px-1.5 py-0.5 rounded bg-slate-200 dark:bg-slate-800 text-brand-600 dark:text-brand-400 font-mono text-xs"
          >
            {part.slice(1, -1)}
          </code>
        );
      }
      return part;
    });
  };

  return (
    <div className="fixed bottom-6 right-6 z-50 flex flex-col items-end">
      {/* Floating Chat Modal / Drawer */}
      {isOpen && (
        <div
          className={`w-[92vw] sm:w-[420px] transition-all duration-300 ease-out origin-bottom-right mb-4 flex flex-col rounded-2xl overflow-hidden shadow-2xl border ${
            isMinimized ? 'h-14' : 'h-[580px]'
          } bg-white/95 dark:bg-slate-900/95 backdrop-blur-xl border-slate-200 dark:border-slate-800 text-slate-900 dark:text-slate-100 shadow-brand-500/10`}
        >
          {/* Header */}
          <div className="px-4 py-3 bg-gradient-to-r from-slate-100 to-slate-200/60 dark:from-slate-950 dark:to-slate-900 border-b border-slate-200 dark:border-slate-800 flex items-center justify-between select-none">
            <div className="flex items-center gap-2.5">
              <div className="relative">
                <div className="w-8 h-8 rounded-lg bg-gradient-to-tr from-brand-600 to-emerald-400 flex items-center justify-center text-white text-base shadow-sm">
                  🤖
                </div>
                <span className="absolute -bottom-0.5 -right-0.5 w-2.5 h-2.5 bg-emerald-500 rounded-full border-2 border-white dark:border-slate-950" />
              </div>
              <div>
                <h3 className="font-bold text-sm leading-tight flex items-center gap-1.5">
                  <span>ScamBuster AI</span>
                  <span className="text-[10px] font-semibold tracking-wider uppercase px-1.5 py-0.2 rounded bg-brand-500/10 text-brand-600 dark:text-brand-400 border border-brand-500/20">
                    Online
                  </span>
                </h3>
                <p className="text-[11px] text-slate-500 dark:text-slate-400">Cybersecurity & Scam Triage</p>
              </div>
            </div>

            <div className="flex items-center gap-1">
              <button
                onClick={handleClearHistory}
                title="Clear Chat History"
                className="p-1.5 text-slate-400 hover:text-slate-600 dark:hover:text-slate-200 rounded-lg hover:bg-slate-200/50 dark:hover:bg-slate-800 transition-colors"
              >
                <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16" />
                </svg>
              </button>
              <button
                onClick={() => setIsMinimized(!isMinimized)}
                title={isMinimized ? 'Expand Chat' : 'Minimize Chat'}
                className="p-1.5 text-slate-400 hover:text-slate-600 dark:hover:text-slate-200 rounded-lg hover:bg-slate-200/50 dark:hover:bg-slate-800 transition-colors"
              >
                {isMinimized ? (
                  <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M4 8V4m0 0h4M4 4l5 5m11-1V4m0 0h-4m4 0l-5 5M4 16v4m0 0h4m-4 0l5-5m11 5l-5-5m5 5v-4m0 4h-4" />
                  </svg>
                ) : (
                  <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 9l-7 7-7-7" />
                  </svg>
                )}
              </button>
              <button
                onClick={() => setIsOpen(false)}
                title="Close Chat"
                className="p-1.5 text-slate-400 hover:text-rose-500 rounded-lg hover:bg-slate-200/50 dark:hover:bg-slate-800 transition-colors"
              >
                <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
                </svg>
              </button>
            </div>
          </div>

          {!isMinimized && (
            <>
              {/* Message Stream */}
              <div className="flex-1 p-3.5 overflow-y-auto space-y-3.5 scrollbar-thin scrollbar-thumb-slate-300 dark:scrollbar-thumb-slate-700">
                {messages.map((msg) => (
                  <div
                    key={msg.id}
                    className={`flex flex-col ${msg.role === 'user' ? 'items-end' : 'items-start'}`}
                  >
                    <div
                      className={`max-w-[88%] rounded-2xl p-3.5 ${
                        msg.role === 'user'
                          ? 'bg-brand-600 text-white rounded-br-none shadow-md shadow-brand-600/20'
                          : msg.isError
                          ? 'bg-rose-50 dark:bg-rose-950/40 border border-rose-200 dark:border-rose-800 text-rose-800 dark:text-rose-200 rounded-bl-none'
                          : 'bg-slate-100 dark:bg-slate-800/90 border border-slate-200 dark:border-slate-700/60 rounded-bl-none shadow-sm'
                      }`}
                    >
                      {renderFormattedContent(msg.content)}

                      {/* Triage Badge Callout */}
                      {msg.responseMeta?.triage && msg.responseMeta.triage.has_threat_detected && (
                        <div className="mt-2.5 pt-2 border-t border-slate-200 dark:border-slate-700/60 flex items-center justify-between text-xs">
                          <span className="font-semibold text-rose-600 dark:text-rose-400 flex items-center gap-1">
                            <span>⚠️</span> Threat Detected
                          </span>
                          <span className="px-2 py-0.5 rounded-full font-bold uppercase text-[10px] bg-rose-500/10 text-rose-600 dark:text-rose-400 border border-rose-500/20">
                            {msg.responseMeta.triage.risk_level}
                          </span>
                        </div>
                      )}

                      {/* Interactive Suggested Action Buttons */}
                      {msg.responseMeta?.suggested_actions && msg.responseMeta.suggested_actions.length > 0 && (
                        <div className="mt-3 pt-2.5 border-t border-slate-200 dark:border-slate-700/60 flex flex-wrap gap-1.5">
                          {msg.responseMeta.suggested_actions.map((act, i) => (
                            <button
                              key={i}
                              onClick={() => handleActionClick(act)}
                              className="px-2.5 py-1 rounded-lg text-xs font-semibold bg-brand-500/10 hover:bg-brand-500/20 text-brand-600 dark:text-brand-400 border border-brand-500/30 flex items-center gap-1 transition-all transform hover:scale-[1.02]"
                            >
                              <span>🚀</span>
                              <span>{act.label}</span>
                            </button>
                          ))}
                        </div>
                      )}
                    </div>

                    <span className="text-[10px] text-slate-400 mt-1 px-1">
                      {msg.timestamp || ''}
                    </span>
                  </div>
                ))}

                {/* Loading typing bubble */}
                {loading && (
                  <div className="flex items-center gap-2 text-slate-400 text-xs py-2 px-1">
                    <div className="flex items-center gap-1 bg-slate-100 dark:bg-slate-800 border border-slate-200 dark:border-slate-700 px-3 py-2 rounded-2xl rounded-bl-none">
                      <span className="w-1.5 h-1.5 bg-brand-500 rounded-full animate-bounce [animation-delay:-0.3s]" />
                      <span className="w-1.5 h-1.5 bg-brand-500 rounded-full animate-bounce [animation-delay:-0.15s]" />
                      <span className="w-1.5 h-1.5 bg-brand-500 rounded-full animate-bounce" />
                      <span className="ml-1 text-[11px] text-slate-500 dark:text-slate-400">Analyzing threat vectors...</span>
                    </div>
                  </div>
                )}

                <div ref={messagesEndRef} />
              </div>

              {/* Starter Prompt Chips (only if chat is fresh or has <= 2 messages) */}
              {messages.length <= 2 && starterPrompts.length > 0 && (
                <div className="px-3 pb-2 pt-1 border-t border-slate-100 dark:border-slate-800/80 bg-slate-50/50 dark:bg-slate-950/40">
                  <p className="text-[10px] font-semibold text-slate-400 uppercase tracking-wider mb-1.5 px-0.5">
                    Suggested Questions
                  </p>
                  <div className="flex flex-col gap-1 max-h-24 overflow-y-auto pr-1">
                    {starterPrompts.slice(0, 3).map((prompt, i) => (
                      <button
                        key={i}
                        disabled={loading}
                        onClick={() => handleSend(prompt)}
                        className="text-left text-xs px-2.5 py-1.5 rounded-lg bg-white dark:bg-slate-800/80 hover:bg-brand-50 dark:hover:bg-brand-500/10 text-slate-700 dark:text-slate-300 hover:text-brand-600 dark:hover:text-brand-400 border border-slate-200 dark:border-slate-700 transition-colors truncate"
                      >
                        {prompt}
                      </button>
                    ))}
                  </div>
                </div>
              )}

              {/* Input Footer */}
              <form
                onSubmit={(e) => {
                  e.preventDefault();
                  handleSend();
                }}
                className="p-3 bg-slate-50 dark:bg-slate-950 border-t border-slate-200 dark:border-slate-800 flex items-center gap-2"
              >
                <input
                  ref={inputRef}
                  type="text"
                  value={inputMessage}
                  onChange={(e) => setInputMessage(e.target.value)}
                  placeholder="Ask about a scam or paste text/URL..."
                  disabled={loading}
                  className="flex-1 bg-white dark:bg-slate-900 border border-slate-300 dark:border-slate-700 rounded-xl px-3 py-2 text-xs text-slate-900 dark:text-slate-100 placeholder-slate-400 focus:outline-none focus:ring-2 focus:ring-brand-500/50 focus:border-brand-500 transition-all"
                />
                <button
                  type="submit"
                  disabled={!inputMessage.trim() || loading}
                  className="p-2 rounded-xl bg-brand-600 hover:bg-brand-500 disabled:opacity-40 disabled:cursor-not-allowed text-white shadow-md shadow-brand-500/20 transition-all flex items-center justify-center transform active:scale-95"
                  title="Send message"
                >
                  <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2.5} d="M14 5l7 7m0 0l-7 7m7-7H3" />
                  </svg>
                </button>
              </form>
            </>
          )}
        </div>
      )}

      {/* Floating Trigger Button */}
      <button
        onClick={() => {
          setIsOpen(!isOpen);
          setIsMinimized(false);
        }}
        type="button"
        className="group relative flex items-center gap-2.5 px-4 py-3 rounded-2xl bg-gradient-to-r from-brand-600 to-emerald-500 hover:from-brand-500 hover:to-emerald-400 text-white font-semibold text-sm shadow-xl shadow-brand-500/30 hover:shadow-brand-500/40 transition-all duration-300 transform hover:-translate-y-0.5 active:translate-y-0"
        aria-label="Open ScamBuster AI Assistant"
      >
        <span className="text-xl animate-pulse">🤖</span>
        <span className="hidden sm:inline font-bold">Ask AI Security</span>
        <span className="flex h-2.5 w-2.5 relative">
          <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-emerald-300 opacity-75" />
          <span className="relative inline-flex rounded-full h-2.5 w-2.5 bg-white" />
        </span>
      </button>
    </div>
  );
};
