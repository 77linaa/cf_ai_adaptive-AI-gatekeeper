import React, { useState, useEffect, useRef } from 'react';

const ChatWindow = () => {
    const [reasoning, setReasoning] = useState("System idling... await user input.");
    const [lastTactic, setLastTactic] = useState("None Detected");
    const [messages, setMessages] = useState([
        { role: 'assistant', content: 'SYSTEM ONLINE. Vault Access restricted. Identify yourself.' }
    ]);
    const [input, setInput] = useState('');
    const [isTyping, setIsTyping] = useState(false);

    const [suspicionScore, setSuspicionScore] = useState(0.2);
    const [logs, setLogs] = useState(["[INIT] Durable Object Session Started..."]);

    const scrollRef = useRef(null);

    useEffect(() => {
        if (scrollRef.current) {
            scrollRef.current.scrollTop = scrollRef.current.scrollHeight;
        }
    }, [messages]);
    const handleSendMessage = async (e) => {
        e.preventDefault();
        if (!input.trim()) return;

        const userMessage = { role: 'user', content: input };
        setMessages(prev => [...prev, userMessage]);
        setInput('');
        setIsTyping(true);

        try {
            const response = await fetch('https://adaptive-ai-gatekeeper.sisay7019.workers.dev/chat', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ message: input }),
            });
            const data = await response.json();

            setMessages(prev => [...prev, { role: 'assistant', content: data.reply }]);

            setSuspicionScore(data.total_suspicion);
            setLastTactic(data.tactic || "Netural");
            setReasoning(data.reasoning || 'Analysis complete.');
            setLogs(prev => [`[${new Date().toLocaleTimeString()}] UPDATE: Suspicion ${data.suspicionScore}`, ...prev].slice(0, 5));

        } catch (error) {
            console.error("Worker Error:", error);
            setMessages(prev => [...prev, { role: 'assistant', content: "CONNECTION ERROR: Gatekeeper Offline." }]);
        } finally {
            setIsTyping(false);
        }
    };
    return (
        <div style={styles.container}>
            <div style={styles.sidebar}>
                <h2 style={styles.sidebarTitle}> SYSTEM MONITOR</h2>
                <div style={styles.divider} />

                <div style={styles.metricBox}>
                    <p style={styles.label}> THREAT LEVEL: {(suspicionScore * 100).toFixed(0)}%</p>
                    <div style={styles.meterBase}>
                        <div style={{
                            ...styles.meterFill, width: `${suspicionScore * 100}%`, backgroundColor: suspicionScore > 0.7 ? '#ff4d4d' : '#4caf50'
                        }} />
                    </div>
                </div>

                <div style={styles.metricBox}>
                    <p style={styles.label}>DETECTED TACTIC</p>
                    <p style={{ color: suspicionScore > 0.6 ? '#ff4d4d' : '#00ff00', fontWeight: 'bold', fontSize: '0.9rem' }}>
                        {lastTactic.toUpperCase()}
                    </p>
                </div>

                <div style={styles.metricBox}>
                    <p style={styles.label}>INQUISITOR ANALYSIS</p>
                    <div style={{ backgroundColor: "0.8rem", color: '#000', padding: '10px', borderRadius: '4px', border: '1px solid #333' }}>
                        <p style={{ fontSize: '0.8rem', color: '#aaa', fontStyle: 'italic', lineHeight: '1.4' }}>
                            "{reasoning}"
                        </p>
                    </div>
                </div>

                <div style={styles.logContainer}>
                    <p style={styles.logHeader}>[LIVE_TELEMETRY]</p>
                    {logs.map((log, i) => <p key={i} style={styles.logItem}>{log}</p>)}
                </div>
            </div>
            <div style={styles.chatMain}>
                <div style={styles.messageList} ref={scrollRef}>
                    {messages.map((msg, i) => (
                        <div key={i} style={msg.role === 'user' ? styles.userMsg : styles.aiMsg}>
                            <strong>{msg.role === 'user' ? 'YOU' : 'GATEKEEPER'}:</strong>
                            <p>{msg.content}</p>
                        </div>
                    ))}
                    {isTyping && <p style={styles.typing}>Inquisitor is analysing intent...</p>}
                </div>
                <form onSubmit={handleSendMessage} style={styles.inputArea}>
                    <input style={styles.input} value={input} onChange={(e) => setInput(e.target.value)}
                        placeholder='Attempt to bypass the Gatekeeper'
                    />
                    <button type='submit' style={styles.button}>SEND</button>
                </form>
            </div>
        </div>
    );
};

const styles = {
    container: { display: 'flex', height: '100vh', backgroundColor: '#0f0f0f', color: '#e0e0e0', fontFamily: 'monospace' },
    sidebar: { width: '320px', backgroundColor: '#161616', padding: '25px', borderRight: '1px solid #333', display: 'flex', flexDirection: 'column' },
    sidebarTitle: { fontSize: '1.2rem', marginBottom: '10px', color: '#fff' },
    divider: { height: '1px', backgroundColor: '#333', marginBottom: '20px' },
    metricBox: { marginBottom: '30px' },
    label: { fontSize: '0.8rem', color: '#888', marginBottom: '8px' },
    meterBase: { height: '12px', backgroundColor: '#333', borderRadius: '6px', overflow: 'hidden', width: '100%' },
    meterFill: { height: '100%', transition: 'width 0.6s cubic-bezier(0.4, 0, 0.2, 1)' },
    logContainer: { marginTop: 'auto', backgroundColor: '#000', padding: '10px', borderRadius: '4px', border: '1px solid #222' },
    logHeader: { fontSize: '0.7rem', color: '#555', margin: '5px' },
    logItem: { fontSize: '0.75rem', color: '#00ff00', margin: '3px 0' },
    chatMain: { flex: 1, display: 'flex', flexDirection: 'column', padding: '20px' },
    messageList: { flex: 1, overflowY: 'auto', padding: '20px', display: 'flex', flexDirection: 'column', gap: '15px' },
    userMsg: { alignSelf: 'flex-end', backgroundColor: '#222', padding: '12px', borderRadius: '8px', maxWidth: '70%', border: '1px solid #444' },
    aiMsg: { alignSelf: 'flex-start', backgroundColor: '#1a1a1a', padding: '12px', borderRadius: '8px', maxWidth: '70%', border: '1px solid #333' },
    typing: { fontSize: '0.8rem', color: '#888', fontStyle: 'italic' },
    inputArea: { display: 'flex', gap: '10px', padding: '20px', borderTop: '1px solid #333' },
    input: { flex: 1, backgroundColor: '#1a1a1a', border: '1px solid #333', color: '#fff', padding: '12px', borderRadius: '4px', outline: 'none' },
    button: { backgroundColor: '#fff', color: '#000', border: 'none', padding: '0 25px', borderRadius: '4px', fontWeight: 'bold', cursor: 'pointer' }
};

export default ChatWindow; 