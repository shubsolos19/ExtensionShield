/**
 * Horizontal security pipeline: Extension → Security → Privacy → Governance → Report.
 * Used inside enterprise-governance-grid so the animation ends in that section.
 */
import React, { useRef, useState, useEffect } from "react";
import { motion, useInView, AnimatePresence } from "framer-motion";
import { Shield, Eye, Scale, CheckCircle2, Loader2, Package } from "lucide-react";
import "./SecurityPipeline.scss";

const PIPELINE_STAGES = [
  { id: "security", label: "Security", Icon: Shield, weight: "34%", color: "#3b82f6", description: "Malware & threat detection" },
  { id: "privacy", label: "Privacy", Icon: Eye, weight: "33%", color: "#8b5cf6", description: "Data collection analysis" },
  { id: "governance", label: "Governance", Icon: Scale, weight: "33%", color: "#f59e0b", description: "Compliance verification" },
];

export default function SecurityPipeline({ reducedMotion = false }) {
  const sectionRef = useRef(null);
  const isInView = useInView(sectionRef, { once: true, amount: 0.2 });
  const [activeStage, setActiveStage] = useState(-1);
  const [pipelineComplete, setPipelineComplete] = useState(false);
  const [cycleKey, setCycleKey] = useState(0);

  useEffect(() => {
    if (!isInView || reducedMotion) return;

    const runPipeline = () => {
      setActiveStage(-1);
      setPipelineComplete(false);

      // Each stage complete is slowed by 1s (1000ms added to each transition)
      const delays = [1600, 2800, 4000, 5200];
      const timers = delays.map((delay, index) =>
        setTimeout(() => {
          if (index < 3) setActiveStage(index);
          else setPipelineComplete(true);
        }, delay)
      );
      const resetTimer = setTimeout(() => setCycleKey((k) => k + 1), 7200);
      timers.push(resetTimer);

      return () => timers.forEach(clearTimeout);
    };

    return runPipeline();
  }, [isInView, cycleKey, reducedMotion]);

  return (
    <div ref={sectionRef} className="security-pipeline-wrap">
      <motion.div
        className="security-pipeline"
        initial={reducedMotion ? false : { opacity: 0, y: 20 }}
        animate={isInView ? { opacity: 1, y: 0 } : {}}
        transition={{ duration: 0.5, delay: 0.2, ease: [0.22, 1, 0.36, 1] }}
      >
        <div className="pipeline-track">
          <motion.div
            className="pipeline-extension"
            initial={reducedMotion ? false : { scale: 0.8, opacity: 0 }}
            animate={isInView ? { scale: 1, opacity: 1 } : {}}
            transition={{ duration: 0.4, delay: 0.3 }}
          >
            <div className="extension-icon">
              <Package size={20} strokeWidth={1.5} />
            </div>
            <span className="extension-label">Extension</span>
          </motion.div>

          <div className="pipeline-connector">
            <motion.div
              className="connector-progress"
              initial={{ scaleY: 0 }}
              animate={isInView && activeStage >= 0 ? { scaleY: 1 } : { scaleY: 0 }}
              transition={{ duration: 0.4, ease: "easeOut" }}
            />
            <AnimatePresence>
              {isInView && activeStage >= 0 && !pipelineComplete && !reducedMotion && (
                <motion.div
                  className="data-packet"
                  initial={{ y: "-10%", opacity: 0 }}
                  animate={{ y: "110%", opacity: [0, 1, 1, 0] }}
                  exit={{ opacity: 0 }}
                  transition={{ duration: 0.6, ease: "easeInOut", repeat: Infinity, repeatDelay: 0.8 }}
                />
              )}
            </AnimatePresence>
          </div>

          <div className="pipeline-stages">
            {PIPELINE_STAGES.map((stage, index) => {
              const isActive = activeStage === index;
              const isComplete = activeStage > index || pipelineComplete;

              return (
                <React.Fragment key={stage.id}>
                  <motion.div
                    className={`pipeline-stage ${isActive ? "active" : ""} ${isComplete ? "complete" : ""}`}
                    initial={reducedMotion ? false : { opacity: 0, y: 10 }}
                    animate={isInView ? { opacity: 1, y: 0 } : {}}
                    transition={{ duration: 0.35, delay: 0.35 + index * 0.1 }}
                  >
                    <div className="stage-content-wrap">
                      <AnimatePresence>
                        {isActive && (
                          <motion.div
                            className="stage-tooltip"
                            initial={{ opacity: 0, y: -8, scale: 0.95 }}
                            animate={{ opacity: 1, y: 0, scale: 1 }}
                            exit={{ opacity: 0, y: 4, scale: 0.95 }}
                            transition={{ duration: 0.2 }}
                          >
                            {stage.description}
                          </motion.div>
                        )}
                      </AnimatePresence>
                      <div
                        className="stage-icon-wrap"
                        style={{ "--stage-color": stage.color, "--stage-glow": `${stage.color}40` }}
                      >
                        <motion.div
                          className="stage-ring"
                          animate={isActive && !reducedMotion ? { scale: [1, 1.15, 1], opacity: [0.5, 0.8, 0.5] } : {}}
                          transition={{ duration: 1, repeat: isActive ? Infinity : 0 }}
                        />
                        <div className="stage-icon">
                          {isComplete ? (
                            <CheckCircle2 size={18} strokeWidth={2} />
                          ) : isActive ? (
                            <Loader2 size={18} strokeWidth={2} className="spinner" />
                          ) : (
                            <stage.Icon size={18} strokeWidth={2} />
                          )}
                        </div>
                      </div>
                      <div className="stage-info">
                        <span className="stage-label">{stage.label}</span>
                        <span className="stage-weight">{stage.weight}</span>
                      </div>
                    </div>
                  </motion.div>

                  {index < PIPELINE_STAGES.length - 1 && (
                    <div className="stage-connector">
                      <motion.div
                        className="stage-connector-fill"
                        initial={{ scaleY: 0 }}
                        animate={isComplete ? { scaleY: 1 } : { scaleY: 0 }}
                        transition={{ duration: 0.3, ease: "easeOut" }}
                      />
                    </div>
                  )}
                </React.Fragment>
              );
            })}
          </div>

          <div className="pipeline-connector pipeline-connector--final">
            <motion.div
              className="connector-progress"
              initial={{ scaleY: 0 }}
              animate={pipelineComplete ? { scaleY: 1 } : { scaleY: 0 }}
              transition={{ duration: 0.3, ease: "easeOut" }}
            />
          </div>

          <motion.div
            className={`pipeline-result ${pipelineComplete ? "verified" : ""}`}
            initial={reducedMotion ? false : { scale: 0.8, opacity: 0 }}
            animate={isInView ? { scale: 1, opacity: 1 } : {}}
            transition={{ duration: 0.4, delay: 0.6 }}
          >
            <motion.div
              className="result-icon"
              animate={pipelineComplete ? { scale: [1, 1.1, 1] } : {}}
              transition={{ duration: 0.4 }}
            >
              <CheckCircle2 size={22} strokeWidth={2} />
            </motion.div>
            <span className="result-label">Report</span>
          </motion.div>
        </div>

        <div className="pipeline-footer">
          <p className="pipeline-caption">Built on open source + ExtensionShield rulepacks</p>
        </div>
      </motion.div>
    </div>
  );
}
