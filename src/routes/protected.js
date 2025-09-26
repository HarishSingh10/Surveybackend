const express = require("express");
const router = express.Router();
const { Pool } = require("pg");
const authMiddleware = require("../middleware/auth");

// ✅ Postgres pool
const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: { rejectUnauthorized: false },
});

// ---------------- GET USER PROFILE ----------------
router.get("/profile", authMiddleware, async (req, res) => {
    try {
        const result = await pool.query(
            `SELECT id, first_name, last_name, email, address, phone, profile_image, has_business, created_at, updated_at
             FROM users
             WHERE id=$1`,
            [req.user.id]
        );

        if (result.rows.length === 0) {
            return res.status(404).json({ message: "User not found" });
        }

        const user = result.rows[0];
        res.json({ user });
    } catch (err) {
        res.status(500).json({ message: "Server error", error: err.message });
    }
});

// ---------------- UPDATE USER PROFILE ----------------
router.put("/update-profile", authMiddleware, async (req, res) => {
    try {
        const updates = { ...req.body };

        // Restrict sensitive updates
        delete updates.role;
        delete updates.refresh_token;
        delete updates.password;
        delete updates.is_verified;

        if (Object.keys(updates).length === 0) {
            return res.status(400).json({ message: "No valid fields to update" });
        }

        // Build dynamic SET query
        const setQuery = Object.keys(updates)
            .map((key, index) => `"${key}"=$${index + 1}`)
            .join(", ");
        const values = Object.values(updates);

        const result = await pool.query(
            `UPDATE users
             SET ${setQuery}, updated_at=NOW()
             WHERE id=$${values.length + 1}
             RETURNING id, first_name, last_name, email, address, phone, profile_image, has_business, created_at, updated_at`,
            [...values, req.user.id]
        );

        if (result.rows.length === 0) {
            return res.status(404).json({ message: "User not found" });
        }

        res.json({
            message: "Profile updated successfully",
            user: result.rows[0],
        });
    } catch (err) {
        res.status(500).json({ message: "Server error", error: err.message });
    }
});
// ✅ GET all feedback forms and latest user responses (with questions + branch) for the logged-in business owner
router.get("/feedback/owner-responses", authMiddleware, async (req, res) => {
    try {
        const ownerId = req.user.id;

        // 1️⃣ Get all businesses owned by this user
        const businessResult = await pool.query(
            "SELECT id FROM businesses WHERE user_id = $1",
            [ownerId]
        );
        const businessIds = businessResult.rows.map(b => b.id);
        if (businessIds.length === 0) {
            return res.json({ success: true, forms: [] });
        }

        // 2️⃣ Get all branches for these businesses
        const branchResult = await pool.query(
            "SELECT id, branch_name FROM branches WHERE business_id = ANY($1)",
            [businessIds]
        );
        const branches = branchResult.rows;
        const branchIds = branches.map(b => b.id);
        if (branchIds.length === 0) {
            return res.json({ success: true, forms: [] });
        }

        // 3️⃣ Get all forms for these branches
        const formsResult = await pool.query(
            "SELECT id, branch_id, form_title, questions FROM feedback_forms WHERE branch_id = ANY($1)",
            [branchIds]
        );
        const forms = formsResult.rows;
        if (forms.length === 0) {
            return res.json({ success: true, forms: [] });
        }

        const formIds = forms.map(f => f.id);

        // 4️⃣ Get only the LATEST response per user per form
        const responsesResult = await pool.query(
            `SELECT fr.*, c.first_name, c.last_name, c.email
             FROM feedback_responses fr
             JOIN coustomer c ON fr.user_iid = c.id
             WHERE fr.id = (
                 SELECT fr2.id
                 FROM feedback_responses fr2
                 WHERE fr2.form_id = fr.form_id AND fr2.user_iid = fr.user_iid
                 ORDER BY fr2.created_at DESC
                 LIMIT 1
             )
             AND fr.form_id = ANY($1)
             ORDER BY fr.created_at DESC`,
            [formIds]
        );
        const responses = responsesResult.rows;

        // 5️⃣ Map responses into structured output
        const formsWithResponses = forms.map(form => {
            // Parse questions safely
            let questions = form.questions;
            if (typeof questions === "string") {
                try { questions = JSON.parse(questions); } catch { questions = []; }
            }

            const formResponses = responses
                .filter(r => r.form_id === form.id)
                .map(r => {
                    let answers = r.answers;

                    // Parse answers safely
                    if (typeof answers === "string") {
                        try { answers = JSON.parse(answers); } catch { answers = []; }
                    }

                    // Normalize answers to always map question → answer
                    const mappedAnswers = Array.isArray(questions)
                        ? questions.map((q, idx) => {
                            let answer = null;

                            // Case 1: answers is an array
                            if (Array.isArray(answers)) {
                                answer = answers[idx] ?? null;
                            }
                            // Case 2: answers is object
                            else if (answers && typeof answers === "object") {
                                answer = answers[idx] || answers[q] || null;
                            }

                            // Case 3: if answer itself is object {answer: "..."}
                            if (answer && typeof answer === "object" && "answer" in answer) {
                                answer = answer.answer;
                            }

                            return { question: q, answer };
                        })
                        : [];

                    return {
                        user: {
                            id: r.user_iid,
                            name: `${r.first_name} ${r.last_name}`,
                            email: r.email
                        },
                        overall_score: r.overall_score,
                        created_at: r.created_at,
                        branch_name: branches.find(b => b.id === form.branch_id)?.branch_name || null,
                        form_title: form.form_title,
                        answers: mappedAnswers
                    };
                });

            return {
                id: form.id,
                form_title: form.form_title,
                branch_name: branches.find(b => b.id === form.branch_id)?.branch_name || null,
                responses: formResponses
            };
        });

        res.json({ success: true, forms: formsWithResponses });
    } catch (err) {
        console.error("❌ Error fetching owner responses:", err);
        res.status(500).json({ success: false, message: err.message });
    }
});


module.exports = router;

