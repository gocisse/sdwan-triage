// SD-WAN Triage Report Visualizations
// Modern Dashboard with Theme Support

// Theme-aware color utilities
function getThemeColors() {
    const isDark = document.documentElement.getAttribute('data-theme') === 'dark';
    return {
        primary: '#3b82f6',
        primaryLight: '#60a5fa',
        success: '#10b981',
        warning: '#f59e0b',
        danger: '#ef4444',
        info: '#06b6d4',
        text: isDark ? '#f1f5f9' : '#1e293b',
        textSecondary: isDark ? '#94a3b8' : '#64748b',
        textMuted: isDark ? '#64748b' : '#94a3b8',
        background: isDark ? '#1e293b' : '#ffffff',
        border: isDark ? '#334155' : '#e2e8f0',
        nodeInternal: '#10b981',
        nodeRouter: '#3b82f6',
        nodeExternal: '#f59e0b',
        nodeAnomaly: '#ef4444'
    };
}

// Utility: Safe D3 initialization wrapper
function safeD3Init(containerId, initFn, data) {
    const container = document.getElementById(containerId);
    if (!container) {
        console.warn(`Container #${containerId} not found`);
        return;
    }
    
    // Remove loading message
    container.style.position = 'relative';
    const loadingMsg = container.querySelector('::before');
    
    if (!data || (Array.isArray(data) && data.length === 0) || 
        (data.nodes && data.nodes.length === 0)) {
        container.innerHTML = '<div style="display: flex; align-items: center; justify-content: center; height: 100%; color: var(--text-muted); font-size: 0.875rem;"><i class="fas fa-info-circle" style="margin-right: 8px;"></i>No data available for visualization</div>';
        return;
    }
    
    try {
        initFn(container, data);
        // Remove loading indicator after successful init
        container.style.minHeight = 'auto';
    } catch (error) {
        console.error(`Error initializing ${containerId}:`, error);
        container.innerHTML = `<div style="display: flex; align-items: center; justify-content: center; height: 100%; color: var(--danger); font-size: 0.875rem;"><i class="fas fa-exclamation-triangle" style="margin-right: 8px;"></i>Error rendering visualization: ${error.message}</div>`;
    }
}

// Network Diagram (Force-Directed Graph) - Enhanced Human-Readable Version
function createNetworkDiagram(container, data) {
    const width = container.clientWidth || 800;
    const height = container.clientHeight || 500;
    
    // Validate data structure
    if (!data.nodes || !data.links) {
        throw new Error('Invalid network data structure');
    }
    
    // Clear existing content
    d3.select(container).selectAll("*").remove();
    
    // Add instructions panel
    const instructions = d3.select(container)
        .append("div")
        .attr("class", "topology-instructions")
        .style("position", "absolute")
        .style("top", "10px")
        .style("right", "10px")
        .style("background", "rgba(255, 255, 255, 0.95)")
        .style("padding", "10px 15px")
        .style("border-radius", "6px")
        .style("box-shadow", "0 2px 8px rgba(0,0,0,0.15)")
        .style("font-size", "12px")
        .style("z-index", "1000")
        .html(`
            <div style="font-weight: 600; margin-bottom: 5px; color: #1e293b;">
                <i class="fas fa-info-circle" style="color: #3b82f6;"></i> Network Topology Guide
            </div>
            <div style="color: #64748b; line-height: 1.6;">
                • <strong>Hover</strong> over nodes to see details<br/>
                • <strong>Drag</strong> nodes to reposition<br/>
                • <strong>Scroll</strong> to zoom in/out<br/>
                • <strong>Click</strong> node to highlight connections
            </div>
        `);
    
    const svg = d3.select(container)
        .append("svg")
        .attr("width", width)
        .attr("height", height)
        .attr("viewBox", [0, 0, width, height])
        .style("background", "#f8fafc");
    
    // Add gradient definitions for links
    const defs = svg.append("defs");
    const gradient = defs.append("linearGradient")
        .attr("id", "link-gradient")
        .attr("gradientUnits", "userSpaceOnUse");
    gradient.append("stop").attr("offset", "0%").attr("stop-color", "#3b82f6").attr("stop-opacity", 0.3);
    gradient.append("stop").attr("offset", "100%").attr("stop-color", "#3b82f6").attr("stop-opacity", 0.8);
    
    // Zoom behavior
    const g = svg.append("g");
    svg.call(d3.zoom()
        .scaleExtent([0.3, 4])
        .on("zoom", (event) => g.attr("transform", event.transform)));
    
    // Enhanced tooltip with better formatting
    const tooltip = d3.select("body").append("div")
        .attr("class", "d3-tooltip")
        .style("opacity", 0)
        .style("max-width", "300px");
    
    // Color scale - theme aware with better colors
    const colors = getThemeColors();
    const colorScale = d3.scaleOrdinal()
        .domain(["internal", "router", "external", "anomaly"])
        .range([colors.nodeInternal, colors.nodeRouter, colors.nodeExternal, colors.nodeAnomaly]);
    
    // Enhanced force simulation with better spacing
    const simulation = d3.forceSimulation(data.nodes)
        .force("link", d3.forceLink(data.links).id(d => d.id).distance(d => {
            // Vary distance based on traffic volume
            const traffic = d.value || 0;
            return traffic > 1000000 ? 100 : 150; // Closer for high-traffic links
        }))
        .force("charge", d3.forceManyBody().strength(-400))
        .force("center", d3.forceCenter(width / 2, height / 2))
        .force("collision", d3.forceCollide().radius(45))
        .force("x", d3.forceX(width / 2).strength(0.05))
        .force("y", d3.forceY(height / 2).strength(0.05));
    
    // Links
    const link = g.append("g")
        .selectAll("line")
        .data(data.links)
        .join("line")
        .attr("stroke", d => d.hasIssue ? "#dc3545" : "#999")
        .attr("stroke-opacity", 0.6)
        .attr("stroke-width", d => Math.max(1, Math.sqrt(d.value || 1)))
        .attr("stroke-dasharray", d => d.hasIssue ? "5,5" : "0");
    
    // Helper function to get human-readable node type
    function getNodeTypeLabel(group) {
        const labels = {
            "internal": "Internal Device",
            "router": "Gateway/Router",
            "external": "External Server",
            "anomaly": "⚠️ Security Alert"
        };
        return labels[group] || group;
    }
    
    // Helper function to format traffic volume
    function formatTrafficVolume(bytes) {
        if (!bytes || bytes === 0) return "No traffic data";
        if (bytes < 1024) return bytes + " B";
        if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(1) + " KB";
        if (bytes < 1024 * 1024 * 1024) return (bytes / (1024 * 1024)).toFixed(1) + " MB";
        return (bytes / (1024 * 1024 * 1024)).toFixed(2) + " GB";
    }
    
    // Enhanced nodes with glow effect for anomalies
    const node = g.append("g")
        .selectAll("g")
        .data(data.nodes)
        .join("g")
        .attr("class", "node-group")
        .call(drag(simulation));
    
    // Add outer glow for anomaly nodes
    node.filter(d => d.group === "anomaly")
        .append("circle")
        .attr("r", 18)
        .attr("fill", "none")
        .attr("stroke", colors.nodeAnomaly)
        .attr("stroke-width", 2)
        .attr("stroke-opacity", 0.3)
        .attr("class", "node-glow");
    
    // Main node circles with size based on traffic
    node.append("circle")
        .attr("r", d => {
            if (d.group === "router") return 14;
            if (d.group === "anomaly") return 12;
            // Size based on traffic volume
            const bytes = d.bytes || 0;
            if (bytes > 10000000) return 12; // > 10MB
            if (bytes > 1000000) return 10;  // > 1MB
            return 8;
        })
        .attr("fill", d => colorScale(d.group))
        .attr("stroke", "#fff")
        .attr("stroke-width", 2.5)
        .attr("class", "node-circle")
        .style("filter", d => d.group === "anomaly" ? "drop-shadow(0 0 6px rgba(239, 68, 68, 0.6))" : "none");
    
    // Add icon overlay for routers and anomalies
    node.filter(d => d.group === "router" || d.group === "anomaly")
        .append("text")
        .attr("text-anchor", "middle")
        .attr("dy", "0.35em")
        .attr("font-size", "10px")
        .attr("fill", "#fff")
        .attr("font-family", "Font Awesome 5 Free")
        .attr("font-weight", "900")
        .text(d => d.group === "router" ? "\uf233" : "\uf071"); // router or warning icon
    
    // Enhanced interaction
    node.on("mouseover", function(event, d) {
            d3.select(this).select(".node-circle")
                .transition().duration(200)
                .attr("r", d => {
                    if (d.group === "router") return 18;
                    if (d.group === "anomaly") return 16;
                    const bytes = d.bytes || 0;
                    if (bytes > 10000000) return 16;
                    if (bytes > 1000000) return 14;
                    return 12;
                })
                .attr("stroke-width", 3);
            
            highlightConnections(d, true);
            
            // Enhanced tooltip with detailed information
            const connections = d.connections || 0;
            const trafficInfo = formatTrafficVolume(d.bytes);
            const nodeType = getNodeTypeLabel(d.group);
            const issueWarning = d.hasIssue ? '<div style="color: #dc3545; font-weight: 600; margin-top: 8px;"><i class="fas fa-exclamation-triangle"></i> Security issues detected</div>' : '';
            
            tooltip.transition().duration(200).style("opacity", 0.95);
            tooltip.html(`
                <div style="font-weight: 600; font-size: 14px; margin-bottom: 8px; color: #1e293b;">
                    <i class="fas fa-network-wired" style="color: ${colorScale(d.group)};"></i> ${d.label || d.id}
                </div>
                <div style="color: #64748b; font-size: 12px; line-height: 1.6;">
                    <div style="margin-bottom: 4px;"><strong>Type:</strong> ${nodeType}</div>
                    <div style="margin-bottom: 4px;"><strong>Traffic:</strong> ${trafficInfo}</div>
                    <div><strong>Connections:</strong> ${connections}</div>
                </div>
                ${issueWarning}
            `)
                .style("left", (event.pageX + 15) + "px")
                .style("top", (event.pageY - 28) + "px");
        })
        .on("mouseout", function(event, d) {
            d3.select(this).select(".node-circle")
                .transition().duration(200)
                .attr("r", d => {
                    if (d.group === "router") return 14;
                    if (d.group === "anomaly") return 12;
                    const bytes = d.bytes || 0;
                    if (bytes > 10000000) return 12;
                    if (bytes > 1000000) return 10;
                    return 8;
                })
                .attr("stroke-width", 2.5);
            
            highlightConnections(d, false);
            tooltip.transition().duration(500).style("opacity", 0);
        })
        .on("click", function(event, d) {
            // Toggle pin on click
            if (d.fx === null) {
                d.fx = d.x;
                d.fy = d.y;
                d3.select(this).select(".node-circle").attr("stroke", "#fbbf24").attr("stroke-width", 4);
            } else {
                d.fx = null;
                d.fy = null;
                d3.select(this).select(".node-circle").attr("stroke", "#fff").attr("stroke-width", 2.5);
            }
        });
    
    // Enhanced labels with better positioning and styling
    const labels = g.append("g")
        .selectAll("text")
        .data(data.nodes)
        .join("text")
        .attr("class", "node-label")
        .attr("dx", 18)
        .attr("dy", 4)
        .attr("font-size", "11px")
        .attr("font-weight", "500")
        .attr("fill", colors.text)
        .attr("stroke", colors.background)
        .attr("stroke-width", 3)
        .attr("paint-order", "stroke")
        .text(d => {
            // Shorten long IP addresses for readability
            const label = d.label || d.id;
            if (label.length > 20) return label.substring(0, 17) + "...";
            return label;
        })
        .style("pointer-events", "none")
        .style("user-select", "none");
    
    // Highlight connections
    function highlightConnections(d, highlight) {
        link.attr("stroke-opacity", l => {
            if (highlight && (l.source.id === d.id || l.target.id === d.id)) return 1;
            return highlight ? 0.1 : 0.6;
        })
        .attr("stroke-width", l => {
            if (highlight && (l.source.id === d.id || l.target.id === d.id)) {
                return Math.max(2, Math.sqrt(l.value || 1) * 1.5);
            }
            return Math.max(1, Math.sqrt(l.value || 1));
        });
        
        node.attr("opacity", n => {
            if (!highlight) return 1;
            if (n.id === d.id) return 1;
            const connected = data.links.some(l => 
                (l.source.id === d.id && l.target.id === n.id) ||
                (l.target.id === d.id && l.source.id === n.id)
            );
            return connected ? 1 : 0.2;
        });
        
        labels.attr("opacity", n => {
            if (!highlight) return 1;
            if (n.id === d.id) return 1;
            const connected = data.links.some(l => 
                (l.source.id === d.id && l.target.id === n.id) ||
                (l.target.id === d.id && l.source.id === n.id)
            );
            return connected ? 1 : 0.3;
        });
    }
    
    // Simulation tick - updated for node groups
    simulation.on("tick", () => {
        link.attr("x1", d => d.source.x)
            .attr("y1", d => d.source.y)
            .attr("x2", d => d.target.x)
            .attr("y2", d => d.target.y);
        
        node.attr("transform", d => `translate(${d.x},${d.y})`);
        labels.attr("x", d => d.x).attr("y", d => d.y);
    });
    
    // Drag behavior
    function drag(simulation) {
        return d3.drag()
            .on("start", (event, d) => {
                if (!event.active) simulation.alphaTarget(0.3).restart();
                d.fx = d.x; d.fy = d.y;
            })
            .on("drag", (event, d) => { 
                d.fx = event.x; 
                d.fy = event.y; 
            })
            .on("end", (event, d) => {
                if (!event.active) simulation.alphaTarget(0);
                // Don't clear fx/fy if node was clicked (pinned)
                // They will be cleared on next click
            });
    }
    
    // Enhanced Legend with better styling
    const legend = svg.append("g")
        .attr("class", "topology-legend")
        .attr("transform", `translate(20, 20)`);
    
    // Legend background
    const legendBg = legend.append("rect")
        .attr("x", -10)
        .attr("y", -10)
        .attr("width", 180)
        .attr("height", 120)
        .attr("fill", "rgba(255, 255, 255, 0.95)")
        .attr("stroke", "#e2e8f0")
        .attr("stroke-width", 1)
        .attr("rx", 6);
    
    // Legend title
    legend.append("text")
        .attr("x", 0)
        .attr("y", 0)
        .attr("font-size", "12px")
        .attr("font-weight", "600")
        .attr("fill", "#1e293b")
        .text("Node Types");
    
    const legendData = [
        { label: "Internal Device", color: colors.nodeInternal, icon: "\uf109" },
        { label: "Gateway/Router", color: colors.nodeRouter, icon: "\uf233" },
        { label: "External Server", color: colors.nodeExternal, icon: "\uf0ac" },
        { label: "Security Alert", color: colors.nodeAnomaly, icon: "\uf071" }
    ];
    
    legendData.forEach((item, i) => {
        const lg = legend.append("g")
            .attr("transform", `translate(0, ${i * 24 + 20})`);
        
        // Circle
        lg.append("circle")
            .attr("r", 7)
            .attr("fill", item.color)
            .attr("stroke", "#fff")
            .attr("stroke-width", 2);
        
        // Icon (for router and anomaly)
        if (item.icon && (i === 1 || i === 3)) {
            lg.append("text")
                .attr("text-anchor", "middle")
                .attr("dy", "0.35em")
                .attr("font-size", "8px")
                .attr("fill", "#fff")
                .attr("font-family", "Font Awesome 5 Free")
                .attr("font-weight", "900")
                .text(item.icon);
        }
        
        // Label
        lg.append("text")
            .attr("x", 16)
            .attr("y", 4)
            .attr("font-size", "11px")
            .attr("fill", colors.text)
            .text(item.label);
    });
    
    // Add traffic indicator legend
    legend.append("text")
        .attr("x", 0)
        .attr("y", 120)
        .attr("font-size", "10px")
        .attr("fill", colors.textMuted)
        .text("💡 Tip: Click node to pin/unpin");
}

// Timeline Visualization
function createTimeline(container, data) {
    const width = container.clientWidth || 800;
    const height = container.clientHeight || 300;
    
    if (!Array.isArray(data) || data.length === 0) {
        throw new Error('No timeline data available');
    }
    const margin = { top: 30, right: 30, bottom: 50, left: 60 };
    const colors = getThemeColors();
    
    d3.select(container).selectAll("*").remove();
    
    const svg = d3.select(container)
        .append("svg")
        .attr("width", width)
        .attr("height", height);
    
    const g = svg.append("g").attr("transform", `translate(${margin.left},${margin.top})`);
    const innerWidth = width - margin.left - margin.right;
    const innerHeight = height - margin.top - margin.bottom;
    
    // Parse timestamps
    const parseTime = d => new Date(d * 1000);
    data.forEach(d => d.time = parseTime(d.timestamp));
    
    // Scales
    const x = d3.scaleTime()
        .domain(d3.extent(data, d => d.time))
        .range([0, innerWidth]);
    
    const eventTypes = [...new Set(data.map(d => d.type))];
    const y = d3.scaleBand()
        .domain(eventTypes)
        .range([0, innerHeight])
        .padding(0.3);
    
    const colorScale = d3.scaleOrdinal()
        .domain(eventTypes)
        .range(d3.schemeCategory10);
    
    // Tooltip
    const tooltip = d3.select("body").append("div")
        .attr("class", "d3-tooltip")
        .style("opacity", 0);
    
    // Axes
    g.append("g")
        .attr("class", "timeline-axis")
        .attr("transform", `translate(0,${innerHeight})`)
        .call(d3.axisBottom(x).ticks(6));
    
    g.append("g")
        .attr("class", "timeline-axis")
        .call(d3.axisLeft(y));
    
    // Events
    g.selectAll(".timeline-event")
        .data(data)
        .join("circle")
        .attr("class", "timeline-event")
        .attr("cx", d => x(d.time))
        .attr("cy", d => y(d.type) + y.bandwidth() / 2)
        .attr("r", 6)
        .attr("fill", d => colorScale(d.type))
        .attr("stroke", "#fff")
        .attr("stroke-width", 1)
        .on("mouseover", function(event, d) {
            d3.select(this).attr("r", 10);
            tooltip.transition().duration(200).style("opacity", 0.9);
            tooltip.html(`<strong>${d.type}</strong><br/>
                Time: ${d.time.toLocaleTimeString()}<br/>
                ${d.source ? 'Source: ' + d.source + '<br/>' : ''}
                ${d.target ? 'Target: ' + d.target + '<br/>' : ''}
                ${d.detail || ''}`)
                .style("left", (event.pageX + 10) + "px")
                .style("top", (event.pageY - 28) + "px");
        })
        .on("mouseout", function() {
            d3.select(this).attr("r", 6);
            tooltip.transition().duration(500).style("opacity", 0);
        });
    
    // Title
    svg.append("text")
        .attr("x", width / 2)
        .attr("y", 15)
        .attr("text-anchor", "middle")
        .attr("font-size", "14px")
        .attr("font-weight", "bold")
        .attr("fill", colors.text)
        .text("Event Timeline");
}

// Sankey Diagram
function createSankeyDiagram(container, data) {
    const width = container.clientWidth || 800;
    const height = container.clientHeight || 400;
    
    if (!data.nodes || !data.links) {
        throw new Error('Invalid sankey data structure');
    }
    const margin = { top: 20, right: 120, bottom: 20, left: 120 };
    const colors = getThemeColors();
    
    d3.select(container).selectAll("*").remove();
    
    if (!data.nodes || !data.links || data.links.length === 0) {
        container.innerHTML = '<div class="viz-error">No traffic flow data available</div>';
        return;
    }
    
    const svg = d3.select(container)
        .append("svg")
        .attr("width", width)
        .attr("height", height);
    
    const g = svg.append("g").attr("transform", `translate(${margin.left},${margin.top})`);
    const innerWidth = width - margin.left - margin.right;
    const innerHeight = height - margin.top - margin.bottom;
    
    // Sankey generator
    const sankey = d3.sankey()
        .nodeWidth(20)
        .nodePadding(15)
        .extent([[0, 0], [innerWidth, innerHeight]]);
    
    const { nodes, links } = sankey({
        nodes: data.nodes.map(d => Object.assign({}, d)),
        links: data.links.map(d => Object.assign({}, d))
    });
    
    // Tooltip
    const tooltip = d3.select("body").append("div")
        .attr("class", "d3-tooltip")
        .style("opacity", 0);
    
    // Color scale
    const color = d3.scaleOrdinal(d3.schemeCategory10);
    
    // Links
    g.append("g")
        .selectAll("path")
        .data(links)
        .join("path")
        .attr("class", "sankey-link")
        .attr("d", d3.sankeyLinkHorizontal())
        .attr("stroke", d => color(d.source.name))
        .attr("stroke-width", d => Math.max(1, d.width))
        .on("mouseover", function(event, d) {
            d3.select(this).attr("stroke-opacity", 0.7);
            tooltip.transition().duration(200).style("opacity", 0.9);
            tooltip.html(`<strong>${d.source.name} → ${d.target.name}</strong><br/>Traffic: ${formatBytes(d.value)}`)
                .style("left", (event.pageX + 10) + "px")
                .style("top", (event.pageY - 28) + "px");
        })
        .on("mouseout", function() {
            d3.select(this).attr("stroke-opacity", 0.4);
            tooltip.transition().duration(500).style("opacity", 0);
        });
    
    // Nodes
    g.append("g")
        .selectAll("rect")
        .data(nodes)
        .join("rect")
        .attr("x", d => d.x0)
        .attr("y", d => d.y0)
        .attr("height", d => Math.max(1, d.y1 - d.y0))
        .attr("width", d => d.x1 - d.x0)
        .attr("fill", d => color(d.name))
        .attr("stroke", "#000")
        .on("mouseover", function(event, d) {
            tooltip.transition().duration(200).style("opacity", 0.9);
            tooltip.html(`<strong>${d.name}</strong><br/>Total: ${formatBytes(d.value)}`)
                .style("left", (event.pageX + 10) + "px")
                .style("top", (event.pageY - 28) + "px");
        })
        .on("mouseout", function() {
            tooltip.transition().duration(500).style("opacity", 0);
        });
    
    // Node labels
    g.append("g")
        .selectAll("text")
        .data(nodes)
        .join("text")
        .attr("x", d => d.x0 < innerWidth / 2 ? d.x1 + 6 : d.x0 - 6)
        .attr("y", d => (d.y1 + d.y0) / 2)
        .attr("dy", "0.35em")
        .attr("text-anchor", d => d.x0 < innerWidth / 2 ? "start" : "end")
        .attr("font-size", "12px")
        .attr("fill", colors.text)
        .text(d => d.name);
}

// Utility: Format bytes
function formatBytes(bytes) {
    if (bytes === 0) return '0 B';
    const k = 1024;
    const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
}

// Protocol Distribution Pie Chart
function createProtocolChart(container, data) {
    const width = container.clientWidth || 400;
    const height = container.clientHeight || 350;
    
    if (!Array.isArray(data) || data.length === 0) {
        throw new Error('No protocol data available');
    }
    const radius = Math.min(width, height) / 2 - 40;
    const colors = getThemeColors();
    
    d3.select(container).selectAll("*").remove();
    
    const svg = d3.select(container)
        .append("svg")
        .attr("width", width)
        .attr("height", height);
    
    const g = svg.append("g")
        .attr("transform", `translate(${width / 2}, ${height / 2})`);
    
    // Tooltip
    const tooltip = d3.select("body").append("div")
        .attr("class", "d3-tooltip")
        .style("opacity", 0);
    
    // Pie generator
    const pie = d3.pie()
        .value(d => d.Bytes)
        .sort(null);
    
    // Arc generator
    const arc = d3.arc()
        .innerRadius(radius * 0.5)
        .outerRadius(radius);
    
    const arcHover = d3.arc()
        .innerRadius(radius * 0.5)
        .outerRadius(radius * 1.1);
    
    // Draw slices
    const slices = g.selectAll("path")
        .data(pie(data))
        .join("path")
        .attr("d", arc)
        .attr("fill", d => d.data.Color || "#667eea")
        .attr("stroke", "white")
        .attr("stroke-width", 2)
        .on("mouseover", function(event, d) {
            d3.select(this).transition().duration(200).attr("d", arcHover);
            tooltip.transition().duration(200).style("opacity", 0.9);
            tooltip.html(`<strong>${d.data.Protocol}</strong><br/>
                ${formatBytes(d.data.Bytes)}<br/>
                ${d.data.Percent.toFixed(1)}%`)
                .style("left", (event.pageX + 10) + "px")
                .style("top", (event.pageY - 28) + "px");
        })
        .on("mouseout", function() {
            d3.select(this).transition().duration(200).attr("d", arc);
            tooltip.transition().duration(500).style("opacity", 0);
        });
    
    // Center text
    g.append("text")
        .attr("text-anchor", "middle")
        .attr("dy", "-0.5em")
        .attr("font-size", "14px")
        .attr("font-weight", "bold")
        .attr("fill", colors.text)
        .text("Protocol");
    
    g.append("text")
        .attr("text-anchor", "middle")
        .attr("dy", "1em")
        .attr("font-size", "12px")
        .attr("fill", colors.textSecondary)
        .text("Distribution");
    
    // Legend
    const legend = svg.append("g")
        .attr("transform", `translate(${width - 120}, 30)`);
    
    data.forEach((d, i) => {
        const lg = legend.append("g")
            .attr("transform", `translate(0, ${i * 25})`);
        lg.append("rect")
            .attr("width", 18)
            .attr("height", 18)
            .attr("fill", d.Color || colors.primary);
        lg.append("text")
            .attr("x", 24)
            .attr("y", 14)
            .attr("font-size", "12px")
            .attr("fill", colors.text)
            .text(`${d.Protocol} (${d.Percent.toFixed(1)}%)`);
    });
}

// Top Talkers Bar Chart
function createTopTalkersChart(container, data) {
    const width = container.clientWidth || 600;
    const height = container.clientHeight || 350;
    
    if (!Array.isArray(data) || data.length === 0) {
        throw new Error('No traffic data available');
    }
    
    // Limit to top 10 for better visualization
    data = data.slice(0, 10);
    const margin = { top: 30, right: 30, bottom: 60, left: 150 };
    const colors = getThemeColors();
    
    d3.select(container).selectAll("*").remove();
    
    if (!data || data.length === 0) {
        container.innerHTML = '<div class="viz-error">No traffic data available</div>';
        return;
    }
    
    const svg = d3.select(container)
        .append("svg")
        .attr("width", width)
        .attr("height", height);
    
    const g = svg.append("g")
        .attr("transform", `translate(${margin.left},${margin.top})`);
    
    const innerWidth = width - margin.left - margin.right;
    const innerHeight = height - margin.top - margin.bottom;
    
    // Tooltip
    const tooltip = d3.select("body").append("div")
        .attr("class", "d3-tooltip")
        .style("opacity", 0);
    
    // Scales
    const x = d3.scaleLinear()
        .domain([0, d3.max(data, d => d.Bytes)])
        .range([0, innerWidth]);
    
    const y = d3.scaleBand()
        .domain(data.map(d => d.IP))
        .range([0, innerHeight])
        .padding(0.2);
    
    // Color scale - theme aware
    const colorScale = d3.scaleOrdinal()
        .domain(["internal", "external"])
        .range([colors.success, colors.primary]);
    
    // Bars
    g.selectAll("rect")
        .data(data)
        .join("rect")
        .attr("x", 0)
        .attr("y", d => y(d.IP))
        .attr("width", d => x(d.Bytes))
        .attr("height", y.bandwidth())
        .attr("fill", d => colorScale(d.Type))
        .attr("rx", 4)
        .on("mouseover", function(event, d) {
            d3.select(this).attr("opacity", 0.8);
            tooltip.transition().duration(200).style("opacity", 0.9);
            tooltip.html(`<strong>${d.IP}</strong><br/>
                Traffic: ${formatBytes(d.Bytes)}<br/>
                ${d.Percent.toFixed(1)}% of total<br/>
                Type: ${d.Type}`)
                .style("left", (event.pageX + 10) + "px")
                .style("top", (event.pageY - 28) + "px");
        })
        .on("mouseout", function() {
            d3.select(this).attr("opacity", 1);
            tooltip.transition().duration(500).style("opacity", 0);
        });
    
    // Labels on bars
    g.selectAll(".bar-label")
        .data(data)
        .join("text")
        .attr("class", "bar-label")
        .attr("x", d => x(d.Bytes) + 5)
        .attr("y", d => y(d.IP) + y.bandwidth() / 2)
        .attr("dy", "0.35em")
        .attr("font-size", "11px")
        .attr("fill", colors.text)
        .text(d => formatBytes(d.Bytes));
    
    // Y axis (IPs)
    g.append("g")
        .call(d3.axisLeft(y))
        .selectAll("text")
        .attr("font-size", "11px");
    
    // X axis
    g.append("g")
        .attr("transform", `translate(0,${innerHeight})`)
        .call(d3.axisBottom(x).ticks(5).tickFormat(d => formatBytes(d)));
    
    // Title
    svg.append("text")
        .attr("x", width / 2)
        .attr("y", 15)
        .attr("text-anchor", "middle")
        .attr("font-size", "14px")
        .attr("font-weight", "bold")
        .attr("fill", colors.text)
        .text("Top Talkers by Traffic Volume");
    
    // Legend
    const legend = svg.append("g")
        .attr("transform", `translate(${width - 150}, ${height - 30})`);
    
    [{ label: "Internal", color: colors.success }, { label: "External", color: colors.primary }].forEach((item, i) => {
        const lg = legend.append("g")
            .attr("transform", `translate(${i * 80}, 0)`);
        lg.append("rect")
            .attr("width", 14)
            .attr("height", 14)
            .attr("fill", item.color);
        lg.append("text")
            .attr("x", 18)
            .attr("y", 11)
            .attr("font-size", "11px")
            .attr("fill", colors.text)
            .text(item.label);
    });
}

// Tab functionality
function initTabs() {
    document.querySelectorAll('.tab').forEach(tab => {
        tab.addEventListener('click', function() {
            const tabGroup = this.closest('.card');
            tabGroup.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
            tabGroup.querySelectorAll('.tab-content').forEach(c => c.classList.remove('active'));
            this.classList.add('active');
            const target = document.getElementById(this.dataset.tab);
            if (target) target.classList.add('active');
        });
    });
}

// Table sorting
function initTableSorting() {
    document.querySelectorAll('.data-table th[data-sort]').forEach(th => {
        th.addEventListener('click', function() {
            const table = this.closest('table');
            const tbody = table.querySelector('tbody');
            const rows = Array.from(tbody.querySelectorAll('tr:not(.action-row)'));
            const col = this.cellIndex;
            const isAsc = this.classList.contains('sort-asc');
            
            rows.sort((a, b) => {
                const aVal = a.cells[col].textContent.trim();
                const bVal = b.cells[col].textContent.trim();
                const aNum = parseFloat(aVal.replace(/[^0-9.-]/g, ''));
                const bNum = parseFloat(bVal.replace(/[^0-9.-]/g, ''));
                
                if (!isNaN(aNum) && !isNaN(bNum)) {
                    return isAsc ? bNum - aNum : aNum - bNum;
                }
                return isAsc ? bVal.localeCompare(aVal) : aVal.localeCompare(bVal);
            });
            
            table.querySelectorAll('th').forEach(h => h.classList.remove('sort-asc', 'sort-desc'));
            this.classList.add(isAsc ? 'sort-desc' : 'sort-asc');
            
            rows.forEach(row => {
                const actionRow = row.nextElementSibling;
                tbody.appendChild(row);
                if (actionRow && actionRow.classList.contains('action-row')) {
                    tbody.appendChild(actionRow);
                }
            });
        });
    });
}

// RTT Distribution Histogram
function createRTTHistogram(container, data) {
    const width = container.clientWidth || 600;
    const height = container.clientHeight || 350;
    
    if (!Array.isArray(data) || data.length === 0) {
        throw new Error('No RTT data available');
    }
    
    const margin = { top: 30, right: 30, bottom: 60, left: 60 };
    const colors = getThemeColors();
    
    d3.select(container).selectAll("*").remove();
    
    const svg = d3.select(container)
        .append("svg")
        .attr("width", width)
        .attr("height", height);
    
    const chartWidth = width - margin.left - margin.right;
    const chartHeight = height - margin.top - margin.bottom;
    
    const g = svg.append("g")
        .attr("transform", `translate(${margin.left},${margin.top})`);
    
    // X scale - categorical (buckets)
    const x = d3.scaleBand()
        .domain(data.map(d => d.bucket))
        .range([0, chartWidth])
        .padding(0.2);
    
    // Y scale - linear (counts)
    const maxCount = d3.max(data, d => d.count) || 0;
    const y = d3.scaleLinear()
        .domain([0, maxCount * 1.1])
        .range([chartHeight, 0]);
    
    // Color scale based on RTT ranges
    const colorScale = d3.scaleOrdinal()
        .domain(["0-10ms", "10-50ms", "50-100ms", "100-200ms", "200-500ms", "500-1000ms", "1000ms+"])
        .range(["#10b981", "#34d399", "#fbbf24", "#fb923c", "#f87171", "#ef4444", "#dc2626"]);
    
    // Add bars
    g.selectAll(".bar")
        .data(data)
        .enter()
        .append("rect")
        .attr("class", "bar")
        .attr("x", d => x(d.bucket))
        .attr("y", d => y(d.count))
        .attr("width", x.bandwidth())
        .attr("height", d => chartHeight - y(d.count))
        .attr("fill", d => colorScale(d.bucket))
        .attr("opacity", 0.8)
        .on("mouseover", function(event, d) {
            d3.select(this).attr("opacity", 1);
            
            const tooltip = d3.select("body").append("div")
                .attr("class", "d3-tooltip")
                .style("position", "absolute")
                .style("left", (event.pageX + 10) + "px")
                .style("top", (event.pageY - 10) + "px")
                .html(`<strong>${d.bucket}</strong><br/>Count: ${d.count.toLocaleString()}`);
        })
        .on("mouseout", function() {
            d3.select(this).attr("opacity", 0.8);
            d3.selectAll(".d3-tooltip").remove();
        });
    
    // Add value labels on top of bars
    g.selectAll(".label")
        .data(data)
        .enter()
        .append("text")
        .attr("class", "label")
        .attr("x", d => x(d.bucket) + x.bandwidth() / 2)
        .attr("y", d => y(d.count) - 5)
        .attr("text-anchor", "middle")
        .attr("font-size", "11px")
        .attr("fill", colors.text)
        .text(d => d.count > 0 ? d.count : "");
    
    // X axis
    g.append("g")
        .attr("class", "timeline-axis")
        .attr("transform", `translate(0,${chartHeight})`)
        .call(d3.axisBottom(x))
        .selectAll("text")
        .attr("transform", "rotate(-45)")
        .style("text-anchor", "end")
        .attr("dx", "-0.8em")
        .attr("dy", "0.15em");
    
    // Y axis
    g.append("g")
        .attr("class", "timeline-axis")
        .call(d3.axisLeft(y).ticks(5));
    
    // Y axis label
    g.append("text")
        .attr("transform", "rotate(-90)")
        .attr("x", -chartHeight / 2)
        .attr("y", -45)
        .attr("text-anchor", "middle")
        .attr("font-size", "12px")
        .attr("fill", colors.text)
        .text("Number of Samples");
    
    // Title
    svg.append("text")
        .attr("x", width / 2)
        .attr("y", 20)
        .attr("text-anchor", "middle")
        .attr("font-size", "14px")
        .attr("font-weight", "bold")
        .attr("fill", colors.text)
        .text("Round-Trip Time (RTT) Distribution");
}

// Toggle action visibility
function toggleAction(btn) {
    const row = btn.closest('tr');
    const actionRow = row.nextElementSibling;
    if (actionRow && actionRow.classList.contains('action-row')) {
        const isVisible = actionRow.classList.contains('show');
        actionRow.classList.toggle('show');
        actionRow.style.display = isVisible ? 'none' : 'table-row';
        btn.textContent = isVisible ? 'Show Action' : 'Hide Action';
    }
}

// Initialize on DOM ready
document.addEventListener('DOMContentLoaded', function() {
    initTabs();
    initTableSorting();
    
    // Add small delay to ensure DOM is fully ready
    setTimeout(function() {
        // Initialize visualizations if data exists
        if (typeof protocolStats !== 'undefined' && protocolStats) {
            safeD3Init('protocol-chart', createProtocolChart, protocolStats);
        }
        if (typeof topTalkers !== 'undefined' && topTalkers) {
            safeD3Init('top-talkers-chart', createTopTalkersChart, topTalkers);
        }
        if (typeof networkData !== 'undefined' && networkData) {
            safeD3Init('network-diagram-viz', createNetworkDiagram, networkData);
        }
        if (typeof timelineData !== 'undefined' && timelineData) {
            safeD3Init('timeline-diagram', createTimeline, timelineData);
        }
        if (typeof sankeyData !== 'undefined' && sankeyData) {
            safeD3Init('sankey-diagram', createSankeyDiagram, sankeyData);
        }
        if (typeof rttHistogramData !== 'undefined' && rttHistogramData) {
            safeD3Init('rtt-histogram', createRTTHistogram, rttHistogramData);
        }
    }, 100);
    
    // Re-render visualizations on window resize
    let resizeTimeout;
    window.addEventListener('resize', function() {
        clearTimeout(resizeTimeout);
        resizeTimeout = setTimeout(function() {
            if (typeof protocolStats !== 'undefined' && protocolStats) {
                safeD3Init('protocol-chart', createProtocolChart, protocolStats);
            }
            if (typeof topTalkers !== 'undefined' && topTalkers) {
                safeD3Init('top-talkers-chart', createTopTalkersChart, topTalkers);
            }
            if (typeof networkData !== 'undefined' && networkData) {
                safeD3Init('network-diagram-viz', createNetworkDiagram, networkData);
            }
            if (typeof timelineData !== 'undefined' && timelineData) {
                safeD3Init('timeline-diagram', createTimeline, timelineData);
            }
            if (typeof sankeyData !== 'undefined' && sankeyData) {
                safeD3Init('sankey-diagram', createSankeyDiagram, sankeyData);
            }
            if (typeof rttHistogramData !== 'undefined' && rttHistogramData) {
                safeD3Init('rtt-histogram', createRTTHistogram, rttHistogramData);
            }
        }, 250);
    });
});

// Copy to clipboard functionality for Wireshark filters
function copyToClipboard(text) {
    if (navigator.clipboard && navigator.clipboard.writeText) {
        navigator.clipboard.writeText(text).then(() => {
            // Show success feedback
            const btn = event.target.closest('.copy-filter-btn');
            if (btn) {
                const originalText = btn.innerHTML;
                btn.innerHTML = '<i class="fas fa-check"></i> Copied!';
                btn.style.background = '#10b981';
                setTimeout(() => {
                    btn.innerHTML = originalText;
                    btn.style.background = '';
                }, 2000);
            }
        }).catch(err => {
            console.error('Failed to copy:', err);
            fallbackCopy(text);
        });
    } else {
        fallbackCopy(text);
    }
}

// Fallback copy method for older browsers
function fallbackCopy(text) {
    const textarea = document.createElement('textarea');
    textarea.value = text;
    textarea.style.position = 'fixed';
    textarea.style.opacity = '0';
    document.body.appendChild(textarea);
    textarea.select();
    try {
        document.execCommand('copy');
        const btn = event.target.closest('.copy-filter-btn');
        if (btn) {
            const originalText = btn.innerHTML;
            btn.innerHTML = '<i class="fas fa-check"></i> Copied!';
            btn.style.background = '#10b981';
            setTimeout(() => {
                btn.innerHTML = originalText;
                btn.style.background = '';
            }, 2000);
        }
    } catch (err) {
        console.error('Fallback copy failed:', err);
        alert('Failed to copy to clipboard. Please copy manually.');
    }
    document.body.removeChild(textarea);
}
