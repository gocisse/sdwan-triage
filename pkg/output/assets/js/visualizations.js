// SD-WAN Triage Report Visualizations - Simplified Implementation
// Clean, minimal D3.js force-directed graph

// Theme-aware color utilities
function getThemeColors() {
    const isDark = document.documentElement.getAttribute('data-theme') === 'dark';
    return {
        primary: '#3b82f6',
        success: '#10b981',
        warning: '#f59e0b',
        danger: '#ef4444',
        text: isDark ? '#f1f5f9' : '#1e293b',
        background: isDark ? '#1e293b' : '#ffffff',
        border: isDark ? '#334155' : '#e2e8f0'
    };
}

// Network Diagram - Simple, Clean Force-Directed Graph
function createNetworkDiagram(container, data) {
    // Clear existing content
    d3.select(container).selectAll("*").remove();
    
    // Validate data
    if (!data || !data.nodes || !data.links || data.nodes.length === 0) {
        container.innerHTML = '<div style="padding: 40px; text-align: center; color: #64748b;">No network data available</div>';
        return;
    }
    
    // Dimensions
    const width = container.clientWidth || 800;
    const height = 500;
    
    // Create SVG with white background
    const svg = d3.select(container)
        .append("svg")
        .attr("width", width)
        .attr("height", height)
        .style("background", "#ffffff")
        .style("border", "1px solid #e0e0e0")
        .style("border-radius", "8px");
    
    // Create main group for zoom/pan
    const g = svg.append("g");
    
    // Add zoom behavior
    svg.call(d3.zoom()
        .scaleExtent([0.5, 3])
        .on("zoom", (event) => g.attr("transform", event.transform)));
    
    // Define arrowhead marker - CRITICAL: markerUnits prevents scaling issues
    svg.append("defs")
        .append("marker")
        .attr("id", "arrow")
        .attr("viewBox", "0 -5 10 10")
        .attr("refX", 12)
        .attr("refY", 0)
        .attr("markerWidth", 3)
        .attr("markerHeight", 3)
        .attr("markerUnits", "strokeWidth")
        .attr("orient", "auto")
        .append("path")
        .attr("d", "M0,-5L10,0L0,5")
        .attr("fill", "#94a3b8");
    
    // Simple color mapping
    const nodeColors = {
        "internal": "#10b981",
        "router": "#3b82f6",
        "external": "#f59e0b",
        "anomaly": "#ef4444"
    };
    
    // Create tooltip
    const tooltip = d3.select("body")
        .append("div")
        .attr("class", "d3-tooltip")
        .style("position", "absolute")
        .style("opacity", 0)
        .style("background", "rgba(0,0,0,0.8)")
        .style("color", "white")
        .style("padding", "8px 12px")
        .style("border-radius", "4px")
        .style("font-size", "12px")
        .style("pointer-events", "none")
        .style("z-index", "10000");
    
    // Simple force simulation
    const simulation = d3.forceSimulation(data.nodes)
        .force("link", d3.forceLink(data.links).id(d => d.id).distance(100))
        .force("charge", d3.forceManyBody().strength(-300))
        .force("center", d3.forceCenter(width / 2, height / 2))
        .force("collision", d3.forceCollide().radius(30));
    
    // Draw links
    const link = g.append("g")
        .selectAll("line")
        .data(data.links)
        .join("line")
        .attr("stroke", d => d.hasIssue ? "#ef4444" : "#cbd5e1")
        .attr("stroke-width", d => {
            const bytes = d.value || 0;
            if (bytes > 10000000) return 3;
            if (bytes > 1000000) return 2;
            return 1;
        })
        .attr("stroke-dasharray", d => d.hasIssue ? "4,4" : "0")
        .attr("marker-end", "url(#arrow)");
    
    // Draw nodes
    const node = g.append("g")
        .selectAll("circle")
        .data(data.nodes)
        .join("circle")
        .attr("r", d => d.group === "router" ? 10 : 8)
        .attr("fill", d => nodeColors[d.group] || "#94a3b8")
        .attr("stroke", "#fff")
        .attr("stroke-width", 2)
        .style("cursor", "pointer")
        .call(d3.drag()
            .on("start", dragStarted)
            .on("drag", dragged)
            .on("end", dragEnded))
        .on("mouseover", function(event, d) {
            d3.select(this)
                .attr("stroke-width", 3)
                .attr("r", d.group === "router" ? 12 : 10);
            
            tooltip.transition().duration(200).style("opacity", 1);
            tooltip.html(`
                <strong>${d.id}</strong><br/>
                Type: ${d.group}<br/>
                ${d.bytes ? `Traffic: ${formatBytes(d.bytes)}` : ''}
            `)
                .style("left", (event.pageX + 10) + "px")
                .style("top", (event.pageY - 10) + "px");
        })
        .on("mouseout", function(event, d) {
            d3.select(this)
                .attr("stroke-width", 2)
                .attr("r", d.group === "router" ? 10 : 8);
            
            tooltip.transition().duration(500).style("opacity", 0);
        });
    
    // Add labels
    const label = g.append("g")
        .selectAll("text")
        .data(data.nodes)
        .join("text")
        .text(d => d.id)
        .attr("font-size", "11px")
        .attr("dx", 12)
        .attr("dy", 4)
        .attr("fill", "#1e293b")
        .attr("stroke", "#fff")
        .attr("stroke-width", 3)
        .attr("paint-order", "stroke")
        .style("pointer-events", "none");
    
    // Update positions on simulation tick
    simulation.on("tick", () => {
        link
            .attr("x1", d => d.source.x)
            .attr("y1", d => d.source.y)
            .attr("x2", d => d.target.x)
            .attr("y2", d => d.target.y);
        
        node
            .attr("cx", d => d.x)
            .attr("cy", d => d.y);
        
        label
            .attr("x", d => d.x)
            .attr("y", d => d.y);
    });
    
    // Drag functions
    function dragStarted(event, d) {
        if (!event.active) simulation.alphaTarget(0.3).restart();
        d.fx = d.x;
        d.fy = d.y;
    }
    
    function dragged(event, d) {
        d.fx = event.x;
        d.fy = event.y;
    }
    
    function dragEnded(event, d) {
        if (!event.active) simulation.alphaTarget(0);
        d.fx = null;
        d.fy = null;
    }
    
    // Helper function
    function formatBytes(bytes) {
        if (bytes < 1024) return bytes + ' B';
        if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(1) + ' KB';
        if (bytes < 1024 * 1024 * 1024) return (bytes / (1024 * 1024)).toFixed(1) + ' MB';
        return (bytes / (1024 * 1024 * 1024)).toFixed(2) + ' GB';
    }
    
    // Add simple legend
    const legend = svg.append("g")
        .attr("transform", `translate(20, ${height - 120})`);
    
    legend.append("rect")
        .attr("width", 160)
        .attr("height", 110)
        .attr("fill", "rgba(255,255,255,0.95)")
        .attr("stroke", "#e0e0e0")
        .attr("rx", 4);
    
    const legendItems = [
        { label: "Internal", color: "#10b981" },
        { label: "Router", color: "#3b82f6" },
        { label: "External", color: "#f59e0b" },
        { label: "Anomaly", color: "#ef4444" }
    ];
    
    legendItems.forEach((item, i) => {
        const lg = legend.append("g")
            .attr("transform", `translate(10, ${i * 25 + 15})`);
        
        lg.append("circle")
            .attr("r", 6)
            .attr("fill", item.color)
            .attr("stroke", "#fff")
            .attr("stroke-width", 1);
        
        lg.append("text")
            .attr("x", 15)
            .attr("y", 4)
            .attr("font-size", "12px")
            .attr("fill", "#1e293b")
            .text(item.label);
    });
}

// Placeholder functions for other visualizations
function createTimeline(container, data) {
    container.innerHTML = '<div style="padding: 20px; text-align: center; color: #64748b;">Timeline visualization</div>';
}

function createSankeyDiagram(container, data) {
    container.innerHTML = '<div style="padding: 20px; text-align: center; color: #64748b;">Sankey diagram</div>';
}

function createRTTHistogram(container, data) {
    container.innerHTML = '<div style="padding: 20px; text-align: center; color: #64748b;">RTT histogram</div>';
}
