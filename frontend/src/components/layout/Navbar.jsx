export default function Navbar() {
    return (
        <nav className="border-b border-border px-6 py-4">
            <div className="container mx-auto flex items-center gap-3">
                <span className="text-xl font-bold text-red-300">LynxMap</span>
                <span className="text-muted-foreground text-sm">
                    Network Vulnerability Scanner
                </span>
            </div>
        </nav>
    )
}
